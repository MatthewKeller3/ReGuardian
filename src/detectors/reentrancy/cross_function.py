"""
Cross-Function Reentrancy Detector

Detects reentrancy vulnerabilities that span multiple functions
within the same contract, exploiting shared state.

Example: withdraw() makes external call, attacker re-enters via transfer()
which uses the same balance mapping before it's updated.
"""

import re
import uuid
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple

from .base import (
    ReentrancyDetector,
    ReentrancyVulnerability,
    ReentrancyType,
    Severity,
    VulnerabilityLocation,
    extract_solidity_functions,
)


class CrossFunctionReentrancyDetector(ReentrancyDetector):
    """
    Detector for cross-function reentrancy vulnerabilities.
    
    Analyzes contracts for:
    1. Functions that make external calls
    2. Other functions that modify the same state variables
    3. Missing reentrancy guards on related functions
    """
    
    @property
    def name(self) -> str:
        return "Cross-Function Reentrancy Detector"
    
    @property
    def description(self) -> str:
        return (
            "Detects reentrancy vulnerabilities where an attacker can exploit "
            "shared state between multiple functions. During an external call "
            "in one function, the attacker re-enters through a different function "
            "that modifies the same state."
        )
    
    @property
    def reentrancy_type(self) -> ReentrancyType:
        return ReentrancyType.CROSS_FUNCTION
    
    def analyze(self, contract_path: Path) -> List[ReentrancyVulnerability]:
        """
        Analyze a contract for cross-function reentrancy.
        
        Args:
            contract_path: Path to the Solidity file
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        with open(contract_path, 'r') as f:
            source_code = f.read()
        
        has_oz_guard = self.check_openzeppelin_guard(source_code)
        
        # Extract all functions and their properties
        functions = self._extract_functions_detailed(source_code)
        
        # Find state variables
        state_vars = self._extract_state_variables(source_code)
        
        # Analyze function interactions
        for func_name, func_info in functions.items():
            if not func_info['has_external_call']:
                continue
            
            # Find functions that share state with this one
            shared_state_funcs = self._find_shared_state_functions(
                func_name, func_info, functions, state_vars
            )
            
            for related_func, shared_vars in shared_state_funcs:
                # Check if both functions have reentrancy protection
                if (func_info['has_protection'] and 
                    functions[related_func]['has_protection']):
                    continue
                
                vuln = self._create_vulnerability(
                    primary_func=func_name,
                    primary_info=func_info,
                    related_func=related_func,
                    related_info=functions[related_func],
                    shared_vars=shared_vars,
                    contract_path=str(contract_path),
                    has_oz_guard=has_oz_guard,
                )
                
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def analyze_bytecode(self, bytecode: str) -> List[ReentrancyVulnerability]:
        """
        Bytecode analysis for cross-function reentrancy is complex
        and requires CFG construction. This is a placeholder.
        """
        # For bytecode analysis, we'd need to:
        # 1. Build control flow graph
        # 2. Identify function selectors
        # 3. Track storage slot access patterns
        # 4. Detect shared storage between functions with CALL opcodes
        
        return []  # Requires more sophisticated analysis
    
    def _extract_functions_detailed(
        self, source_code: str
    ) -> Dict[str, Dict[str, Any]]:
        """
        Extract detailed function information including:
        - State variables read/written
        - External calls made
        - Protection mechanisms
        """
        functions = extract_solidity_functions(source_code)
        
        for func_info in functions.values():
            func_body = func_info['body']
            func_modifiers = func_info['modifiers']
            
            # Analyze function
            func_info.update({
                'has_external_call': self._has_external_call(func_body),
                'has_protection': self._has_reentrancy_protection(func_info['code']),
                'state_reads': self._find_state_reads(func_body),
                'state_writes': self._find_state_writes(func_body),
                'visibility': self._get_visibility(func_modifiers),
            })
        
        return functions
    
    def _extract_state_variables(self, source_code: str) -> Set[str]:
        """Extract state variable names from contract."""
        state_vars = set()
        
        # Match state variable declarations
        # mapping(...) name;
        # type name;
        # type[] name;
        patterns = [
            r'mapping\s*\([^)]+\)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*;',
            r'(?:uint\d*|int\d*|address|bool|bytes\d*|string)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*;',
            r'(?:uint\d*|int\d*|address|bool)\[\]\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*;',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, source_code):
                state_vars.add(match.group(1))
        
        return state_vars
    
    def _has_external_call(self, func_body: str) -> bool:
        """Check if function makes external calls."""
        patterns = [
            r'\.call\s*[\({]',
            r'\.send\s*\(',
            r'\.transfer\s*\(',
            r'\.delegatecall\s*\(',
            r'\.staticcall\s*\(',
        ]
        return any(re.search(p, func_body) for p in patterns)
    
    def _has_reentrancy_protection(self, func_code: str) -> bool:
        """Check if function has reentrancy protection."""
        patterns = [
            r'nonReentrant',
            r'noReentrant',
            r'mutex',
            r'locked\s*==\s*false',
            r'_status\s*!=\s*_ENTERED',
        ]
        return any(re.search(p, func_code, re.IGNORECASE) for p in patterns)
    
    def _find_state_reads(self, func_body: str) -> Set[str]:
        """Find state variables read in function."""
        reads = set()
        # Look for variable access patterns
        var_pattern = r'\b(\w+)\s*\['  # mapping access
        for match in re.finditer(var_pattern, func_body):
            reads.add(match.group(1))
        return reads
    
    def _find_state_writes(self, func_body: str) -> Set[str]:
        """Find state variables written in function."""
        writes = set()
        # Look for assignment patterns
        patterns = [
            r'(\w+)\s*\[[^\]]+\]\s*[+\-\*\/]?=',  # mapping[key] = 
            r'(\w+)\s*[+\-\*\/]?=\s*[^=]',         # var = (not ==)
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, func_body):
                writes.add(match.group(1))
        return writes
    
    def _get_visibility(self, modifiers: str) -> str:
        """Get function visibility."""
        if 'external' in modifiers:
            return 'external'
        elif 'public' in modifiers:
            return 'public'
        elif 'internal' in modifiers:
            return 'internal'
        elif 'private' in modifiers:
            return 'private'
        return 'public'  # default
    
    def _find_shared_state_functions(
        self,
        func_name: str,
        func_info: Dict[str, Any],
        all_functions: Dict[str, Dict[str, Any]],
        state_vars: Set[str],
    ) -> List[Tuple[str, Set[str]]]:
        """
        Find functions that share state variables with the given function.
        
        Returns list of (function_name, shared_variables) tuples.
        """
        shared = []
        
        # Get state vars accessed by this function
        func_state = func_info['state_reads'] | func_info['state_writes']
        func_state &= state_vars  # Only actual state vars
        
        for other_name, other_info in all_functions.items():
            if other_name == func_name:
                continue
            
            # Skip private/internal functions (harder to exploit)
            if other_info['visibility'] in ('private', 'internal'):
                continue
            
            # Check for shared state
            other_state = other_info['state_reads'] | other_info['state_writes']
            other_state &= state_vars
            
            shared_vars = func_state & other_state
            
            if shared_vars and other_info['state_writes'] & shared_vars:
                # Other function writes to shared state - potential vulnerability
                shared.append((other_name, shared_vars))
        
        return shared
    
    def _create_vulnerability(
        self,
        primary_func: str,
        primary_info: Dict[str, Any],
        related_func: str,
        related_info: Dict[str, Any],
        shared_vars: Set[str],
        contract_path: str,
        has_oz_guard: bool,
    ) -> ReentrancyVulnerability:
        """Create a vulnerability report for cross-function reentrancy."""
        
        shared_vars_str = ', '.join(shared_vars)
        
        return ReentrancyVulnerability(
            id=str(uuid.uuid4()),
            type=ReentrancyType.CROSS_FUNCTION,
            severity=Severity.HIGH,
            title=f"Cross-Function Reentrancy: {primary_func}() ↔ {related_func}()",
            description=(
                f"The function '{primary_func}()' makes an external call and shares "
                f"state variables ({shared_vars_str}) with '{related_func}()'. "
                f"An attacker can re-enter through '{related_func}()' during the "
                f"external call, manipulating shared state before '{primary_func}()' "
                f"completes its state updates."
            ),
            location=VulnerabilityLocation(
                file_path=contract_path,
                contract_name="Unknown",  # Would need AST for accurate name
                function_name=primary_func,
                line_start=primary_info['start_line'],
                line_end=primary_info['start_line'] + primary_info['code'].count('\n'),
            ),
            attack_vector=(
                f"1. Attacker calls {primary_func}()\n"
                f"2. {primary_func}() makes external call to attacker contract\n"
                f"3. Attacker's fallback re-enters via {related_func}()\n"
                f"4. {related_func}() modifies {shared_vars_str} before "
                f"{primary_func}() updates them\n"
                f"5. Attacker exploits inconsistent state"
            ),
            recommendation=(
                f"1. Apply nonReentrant modifier to BOTH {primary_func}() and "
                f"{related_func}()\n"
                f"2. Use OpenZeppelin's ReentrancyGuard\n"
                f"3. Ensure all functions modifying shared state have protection\n"
                f"4. Consider using a global reentrancy lock for the contract"
            ),
            references=[
                "https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard",
                "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
            ],
            confidence=0.75,
            has_reentrancy_guard=has_oz_guard,
            suggested_fix=self._suggest_cross_function_fix_detailed(
                primary_func, related_func, shared_vars
            ),
        )
    
    def _suggest_cross_function_fix_detailed(
        self,
        primary_func: str,
        related_func: str,
        shared_vars: Set[str],
    ) -> str:
        """Generate detailed fix suggestion."""
        return f"""
// Apply ReentrancyGuard to ALL functions that share state
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureContract is ReentrancyGuard {{
    // Shared state: {', '.join(shared_vars)}
    
    function {primary_func}() external nonReentrant {{
        // Update state BEFORE external calls
        // ... state updates ...
        
        // External call LAST
        // (bool success, ) = recipient.call{{value: amount}}("");
    }}
    
    function {related_func}() external nonReentrant {{
        // This function also needs protection since it
        // modifies the same state variables
        // ... implementation ...
    }}
}}
"""
