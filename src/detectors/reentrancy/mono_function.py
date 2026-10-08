"""
Mono-Function Reentrancy Detector

Detects classic reentrancy vulnerabilities where a single function
can be recursively called before state updates complete.

This is the most common type of reentrancy, exemplified by The DAO hack.
"""

import re
import uuid
from pathlib import Path
from typing import List, Optional, Dict, Any

from .base import (
    ReentrancyDetector,
    ReentrancyVulnerability,
    ReentrancyType,
    Severity,
    VulnerabilityLocation,
    extract_solidity_functions,
)


class MonoFunctionReentrancyDetector(ReentrancyDetector):
    """
    Detector for mono-function (single-function) reentrancy vulnerabilities.
    
    Looks for patterns where:
    1. External calls are made (call, send, transfer)
    2. State is updated AFTER the external call
    3. No reentrancy guard is present
    """
    
    @property
    def name(self) -> str:
        return "Mono-Function Reentrancy Detector"
    
    @property
    def description(self) -> str:
        return (
            "Detects reentrancy vulnerabilities within a single function where "
            "external calls are made before state updates, allowing recursive "
            "exploitation."
        )
    
    @property
    def reentrancy_type(self) -> ReentrancyType:
        return ReentrancyType.MONO_FUNCTION
    
    # Patterns for external calls
    EXTERNAL_CALL_PATTERNS = [
        r'\.call\s*\{?\s*value\s*:',  # .call{value: ...}
        r'\.call\s*\(',               # .call(...)
        r'\.send\s*\(',               # .send(...)
        r'\.transfer\s*\(',           # .transfer(...)
        r'\.delegatecall\s*\(',       # .delegatecall(...)
    ]
    
    # Patterns for state modifications
    STATE_MODIFICATION_PATTERNS = [
        r'balances?\s*\[.*\]\s*[+\-\*\/]?=',  # balances[addr] = / += / -=
        r'mapping.*=',                          # mapping assignments
        r'\w+\s*=\s*\d+',                       # variable = number
        r'delete\s+',                           # delete keyword
    ]
    
    # Patterns indicating protection
    PROTECTION_PATTERNS = [
        r'nonReentrant',
        r'ReentrancyGuard',
        r'mutex',
        r'locked\s*=\s*true',
        r'_status\s*=',
    ]
    
    def analyze(self, contract_path: Path) -> List[ReentrancyVulnerability]:
        """
        Analyze a Solidity contract file for mono-function reentrancy.
        
        Args:
            contract_path: Path to the .sol file
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        with open(contract_path, 'r') as f:
            source_code = f.read()
        
        # Check if contract uses OpenZeppelin guard
        has_oz_guard = self.check_openzeppelin_guard(source_code)
        
        # Parse functions from source
        functions = self._extract_functions(source_code)
        
        for func_name, func_info in functions.items():
            func_code = func_info['code']
            start_line = func_info['start_line']
            
            # Skip if function has reentrancy protection
            if self._has_protection(func_code):
                continue
            
            # Check for vulnerable pattern
            vulnerability = self._check_function(
                func_name=func_name,
                func_code=func_code,
                contract_path=str(contract_path),
                contract_name=func_info.get('contract', 'Unknown'),
                start_line=start_line,
                has_oz_guard=has_oz_guard,
            )
            
            if vulnerability:
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def analyze_bytecode(self, bytecode: str) -> List[ReentrancyVulnerability]:
        """
        Analyze EVM bytecode for reentrancy patterns.
        
        This is a more advanced analysis that looks for:
        - CALL opcodes followed by SSTORE
        - Missing reentrancy lock patterns
        
        Args:
            bytecode: Hex-encoded bytecode
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        # Convert to bytes for analysis
        if bytecode.startswith('0x'):
            bytecode = bytecode[2:]
        
        try:
            bytecode_bytes = bytes.fromhex(bytecode)
        except ValueError:
            return vulnerabilities
        
        # Look for CALL (0xF1) followed by SSTORE (0x55)
        # This is a simplified check - real analysis needs CFG
        call_positions = []
        sstore_positions = []
        
        for i, byte in enumerate(bytecode_bytes):
            if byte == 0xF1:  # CALL
                call_positions.append(i)
            elif byte == 0x55:  # SSTORE
                sstore_positions.append(i)
        
        # Check if any SSTORE comes after CALL (potential vulnerability)
        for call_pos in call_positions:
            for sstore_pos in sstore_positions:
                if sstore_pos > call_pos:
                    # Potential vulnerability found
                    vuln = ReentrancyVulnerability(
                        id=str(uuid.uuid4()),
                        type=ReentrancyType.MONO_FUNCTION,
                        severity=Severity.HIGH,
                        title="Potential Reentrancy in Bytecode",
                        description=(
                            f"SSTORE opcode found after CALL opcode at positions "
                            f"{call_pos} and {sstore_pos}. This pattern may indicate "
                            f"state updates after external calls."
                        ),
                        location=VulnerabilityLocation(
                            file_path="bytecode",
                            contract_name="Unknown",
                            function_name="Unknown",
                            line_start=call_pos,
                            line_end=sstore_pos,
                        ),
                        attack_vector=(
                            "An attacker could deploy a malicious contract that "
                            "re-enters the vulnerable function during the CALL, "
                            "before state is updated via SSTORE."
                        ),
                        recommendation=(
                            "Decompile the bytecode and verify the source follows "
                            "the Checks-Effects-Interactions pattern."
                        ),
                        confidence=0.6,
                    )
                    vulnerabilities.append(vuln)
                    break  # One finding per CALL is enough
        
        return vulnerabilities
    
    def _extract_functions(self, source_code: str) -> Dict[str, Dict[str, Any]]:
        """
        Extract function definitions from Solidity source code.
        
        Args:
            source_code: Solidity source code
            
        Returns:
            Dictionary mapping function names to their code and metadata
        """
        current_contract = "Unknown"
        
        # Track current contract
        for line in source_code.split('\n'):
            contract_match = re.search(r'contract\s+(\w+)', line)
            if contract_match:
                current_contract = contract_match.group(1)
        
        functions = extract_solidity_functions(source_code)
        for func_info in functions.values():
            func_info['contract'] = current_contract
        
        return functions
    
    def _has_protection(self, func_code: str) -> bool:
        """Check if function has reentrancy protection."""
        for pattern in self.PROTECTION_PATTERNS:
            if re.search(pattern, func_code, re.IGNORECASE):
                return True
        return False
    
    def _check_function(
        self,
        func_name: str,
        func_code: str,
        contract_path: str,
        contract_name: str,
        start_line: int,
        has_oz_guard: bool,
    ) -> Optional[ReentrancyVulnerability]:
        """
        Check a single function for reentrancy vulnerability.
        
        Args:
            func_name: Name of the function
            func_code: Function source code
            contract_path: Path to the contract file
            contract_name: Name of the contract
            start_line: Starting line number
            has_oz_guard: Whether contract imports ReentrancyGuard
            
        Returns:
            Vulnerability if found, None otherwise
        """
        # Find external calls
        external_call_match = None
        for pattern in self.EXTERNAL_CALL_PATTERNS:
            match = re.search(pattern, func_code)
            if match:
                external_call_match = match
                break
        
        if not external_call_match:
            return None
        
        # Find state modifications
        state_mod_match = None
        for pattern in self.STATE_MODIFICATION_PATTERNS:
            match = re.search(pattern, func_code)
            if match:
                state_mod_match = match
                break
        
        if not state_mod_match:
            return None
        
        # Check if state modification comes AFTER external call
        # (This is the vulnerable pattern)
        if state_mod_match.start() > external_call_match.start():
            # Calculate line numbers
            call_line = func_code[:external_call_match.start()].count('\n')
            mod_line = func_code[:state_mod_match.start()].count('\n')
            
            # Determine severity based on context
            severity = Severity.HIGH
            if 'balance' in func_code.lower() or 'withdraw' in func_name.lower():
                severity = Severity.CRITICAL
            
            # Extract relevant code snippet
            snippet_lines = func_code.split('\n')
            snippet = '\n'.join(snippet_lines[max(0, call_line-2):mod_line+3])
            
            vuln = ReentrancyVulnerability(
                id=str(uuid.uuid4()),
                type=ReentrancyType.MONO_FUNCTION,
                severity=severity,
                title=f"Reentrancy Vulnerability in {func_name}()",
                description=(
                    f"The function '{func_name}' performs an external call before "
                    f"updating state variables. An attacker can recursively call "
                    f"this function before the state update completes, potentially "
                    f"draining funds or corrupting state."
                ),
                location=VulnerabilityLocation(
                    file_path=contract_path,
                    contract_name=contract_name,
                    function_name=func_name,
                    line_start=start_line + call_line,
                    line_end=start_line + mod_line,
                    source_snippet=snippet,
                ),
                attack_vector=(
                    "1. Attacker calls the vulnerable function\n"
                    "2. Function makes external call to attacker's contract\n"
                    "3. Attacker's fallback/receive function re-enters\n"
                    "4. Original state update hasn't happened yet\n"
                    "5. Attacker can repeat until funds drained"
                ),
                recommendation=(
                    "1. Use OpenZeppelin's ReentrancyGuard with nonReentrant modifier\n"
                    "2. Follow Checks-Effects-Interactions pattern:\n"
                    "   - First: Check conditions (require statements)\n"
                    "   - Second: Update state variables\n"
                    "   - Last: Make external calls\n"
                    "3. Consider using pull-over-push pattern for payments"
                ),
                references=[
                    "https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard",
                    "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
                    "https://swcregistry.io/docs/SWC-107",
                ],
                confidence=0.85,
                has_reentrancy_guard=has_oz_guard,
            )
            
            # Generate fix suggestion
            vuln.suggested_fix = self.generate_fix_suggestion(vuln)
            
            return vuln
        
        return None
