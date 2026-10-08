"""
Base Reentrancy Detector

Abstract base class for all reentrancy detection implementations.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
from pathlib import Path


def extract_solidity_functions(source_code: str) -> Dict[str, Dict[str, Any]]:
    """
    Extract function definitions from Solidity source code.

    Uses brace counting to capture full function bodies, since a plain
    regex cannot handle nested braces (e.g. .call{value: ...}, if/for blocks).

    Returns:
        Dictionary mapping function names to:
        - code: full function source (signature + body)
        - params: parameter list text
        - modifiers: text between the parameter list and the opening brace
        - body: function body (between the outer braces)
        - start_line: 1-based line number of the signature
    """
    functions = {}
    sig_pattern = r'function\s+(\w+)\s*\(([^)]*)\)([^{;]*)\{'

    for match in re.finditer(sig_pattern, source_code, re.DOTALL):
        body_start = match.end() - 1  # position of opening brace
        depth = 0
        end_pos = None
        for pos in range(body_start, len(source_code)):
            char = source_code[pos]
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    end_pos = pos + 1
                    break

        if end_pos is None:
            continue  # Unbalanced braces; skip

        functions[match.group(1)] = {
            'code': source_code[match.start():end_pos],
            'params': match.group(2),
            'modifiers': match.group(3),
            'body': source_code[body_start + 1:end_pos - 1],
            'start_line': source_code[:match.start()].count('\n') + 1,
        }

    return functions


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ReentrancyType(Enum):
    """Types of reentrancy vulnerabilities"""
    MONO_FUNCTION = "mono_function"
    CROSS_FUNCTION = "cross_function"
    CROSS_CONTRACT = "cross_contract"
    READ_ONLY = "read_only"


@dataclass
class VulnerabilityLocation:
    """Location of a vulnerability in source code"""
    file_path: str
    contract_name: str
    function_name: str
    line_start: int
    line_end: int
    source_snippet: Optional[str] = None


@dataclass
class ReentrancyVulnerability:
    """Represents a detected reentrancy vulnerability"""
    id: str
    type: ReentrancyType
    severity: Severity
    title: str
    description: str
    location: VulnerabilityLocation
    attack_vector: str
    recommendation: str
    references: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0
    
    # OpenZeppelin specific
    has_reentrancy_guard: bool = False
    suggested_fix: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "type": self.type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "location": {
                "file": self.location.file_path,
                "contract": self.location.contract_name,
                "function": self.location.function_name,
                "lines": f"{self.location.line_start}-{self.location.line_end}",
                "snippet": self.location.source_snippet,
            },
            "attack_vector": self.attack_vector,
            "recommendation": self.recommendation,
            "references": self.references,
            "confidence": self.confidence,
            "has_reentrancy_guard": self.has_reentrancy_guard,
            "suggested_fix": self.suggested_fix,
        }


@dataclass
class AnalysisResult:
    """Result of reentrancy analysis"""
    contract_path: str
    vulnerabilities: List[ReentrancyVulnerability]
    analysis_time_seconds: float
    analyzer_version: str
    warnings: List[str] = field(default_factory=list)
    
    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0
    
    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)


class ReentrancyDetector(ABC):
    """
    Abstract base class for reentrancy detectors.
    
    All specific reentrancy detectors should inherit from this class
    and implement the required methods.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._vulnerabilities: List[ReentrancyVulnerability] = []
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the detector"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Description of what this detector finds"""
        pass
    
    @property
    @abstractmethod
    def reentrancy_type(self) -> ReentrancyType:
        """Type of reentrancy this detector identifies"""
        pass
    
    @abstractmethod
    def analyze(self, contract_path: Path) -> List[ReentrancyVulnerability]:
        """
        Analyze a contract for reentrancy vulnerabilities.
        
        Args:
            contract_path: Path to the Solidity/Vyper contract file
            
        Returns:
            List of detected vulnerabilities
        """
        pass
    
    @abstractmethod
    def analyze_bytecode(self, bytecode: str) -> List[ReentrancyVulnerability]:
        """
        Analyze compiled bytecode for reentrancy vulnerabilities.
        
        Args:
            bytecode: Hex-encoded EVM bytecode
            
        Returns:
            List of detected vulnerabilities
        """
        pass
    
    def check_openzeppelin_guard(self, source_code: str) -> bool:
        """
        Check if the contract uses OpenZeppelin's ReentrancyGuard.
        
        Args:
            source_code: Solidity source code
            
        Returns:
            True if ReentrancyGuard is used
        """
        oz_patterns = [
            "import \"@openzeppelin/contracts/security/ReentrancyGuard.sol\"",
            "import \"@openzeppelin/contracts/utils/ReentrancyGuard.sol\"",
            "import '@openzeppelin/contracts/security/ReentrancyGuard.sol'",
            "is ReentrancyGuard",
            "nonReentrant",
        ]
        return any(pattern in source_code for pattern in oz_patterns)
    
    def check_checks_effects_interactions(self, function_code: str) -> bool:
        """
        Check if a function follows the Checks-Effects-Interactions pattern.
        
        This is a heuristic check - proper analysis requires AST parsing.
        
        Args:
            function_code: Solidity function source code
            
        Returns:
            True if pattern appears to be followed
        """
        # Look for external calls after state changes
        external_call_patterns = [
            ".call{",
            ".call(",
            ".send(",
            ".transfer(",
            "delegatecall(",
        ]
        
        state_change_patterns = [
            "=",  # Assignment
            "+=",
            "-=",
            "delete ",
        ]
        
        # This is a simplified check - real implementation needs AST analysis
        # to properly track the order of operations
        return True  # Placeholder
    
    def generate_fix_suggestion(
        self, 
        vulnerability: ReentrancyVulnerability
    ) -> str:
        """
        Generate a suggested fix for the vulnerability.
        
        Args:
            vulnerability: The detected vulnerability
            
        Returns:
            Suggested code fix
        """
        if vulnerability.type == ReentrancyType.MONO_FUNCTION:
            return self._suggest_mono_function_fix(vulnerability)
        elif vulnerability.type == ReentrancyType.CROSS_FUNCTION:
            return self._suggest_cross_function_fix(vulnerability)
        elif vulnerability.type == ReentrancyType.CROSS_CONTRACT:
            return self._suggest_cross_contract_fix(vulnerability)
        elif vulnerability.type == ReentrancyType.READ_ONLY:
            return self._suggest_read_only_fix(vulnerability)
        return ""
    
    def _suggest_mono_function_fix(self, vuln: ReentrancyVulnerability) -> str:
        return f"""
// Option 1: Use OpenZeppelin's ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract {vuln.location.contract_name} is ReentrancyGuard {{
    function {vuln.location.function_name}() external nonReentrant {{
        // Your code here
    }}
}}

// Option 2: Follow Checks-Effects-Interactions pattern
function {vuln.location.function_name}() external {{
    // 1. CHECKS - Validate conditions
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    // 2. EFFECTS - Update state BEFORE external calls
    balances[msg.sender] -= amount;
    
    // 3. INTERACTIONS - External calls LAST
    (bool success, ) = msg.sender.call{{value: amount}}("");
    require(success, "Transfer failed");
}}
"""
    
    def _suggest_cross_function_fix(self, vuln: ReentrancyVulnerability) -> str:
        return f"""
// Use ReentrancyGuard on ALL functions that share state
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract {vuln.location.contract_name} is ReentrancyGuard {{
    // Apply nonReentrant to all functions that modify shared state
    function withdraw() external nonReentrant {{
        // ...
    }}
    
    function transfer(address to, uint amount) external nonReentrant {{
        // ...
    }}
}}
"""
    
    def _suggest_cross_contract_fix(self, vuln: ReentrancyVulnerability) -> str:
        return """
// For cross-contract reentrancy:
// 1. Use ReentrancyGuard on entry points
// 2. Follow Checks-Effects-Interactions strictly
// 3. Be cautious with callbacks and hooks (ERC777, ERC721)
// 4. Consider using pull-over-push pattern for payments

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/PullPayment.sol";

contract SecureContract is ReentrancyGuard, PullPayment {
    // Use _asyncTransfer instead of direct transfers
    function pay(address payee, uint256 amount) internal {
        _asyncTransfer(payee, amount);
    }
}
"""
    
    def _suggest_read_only_fix(self, vuln: ReentrancyVulnerability) -> str:
        return """
// For read-only reentrancy:
// 1. Don't rely on external contract state during calculations
// 2. Cache values before external calls
// 3. Use reentrancy locks even for view functions if they affect pricing

// Example: Cache LP token price before external interactions
function getPrice() public view returns (uint256) {
    // Cache the value to prevent manipulation
    uint256 cachedReserve = reserve;
    uint256 cachedSupply = totalSupply;
    return cachedReserve * 1e18 / cachedSupply;
}
"""
