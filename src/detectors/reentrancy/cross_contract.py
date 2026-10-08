"""
Cross-Contract Reentrancy Detector

Detects reentrancy vulnerabilities that span multiple contracts,
particularly through callback mechanisms like ERC777, ERC721, and
custom interfaces.

Notable example: Visor Finance hack ($8.2M) via delegatedTransferERC20()
"""

import re
import uuid
from pathlib import Path
from typing import List, Dict, Any, Set

from .base import (
    ReentrancyDetector,
    ReentrancyVulnerability,
    ReentrancyType,
    Severity,
    VulnerabilityLocation,
    extract_solidity_functions,
)


class CrossContractReentrancyDetector(ReentrancyDetector):
    """
    Detector for cross-contract reentrancy vulnerabilities.
    
    Focuses on:
    1. ERC777 token hooks (tokensReceived, tokensToSend)
    2. ERC721 hooks (onERC721Received)
    3. Custom callback interfaces
    4. Flash loan callbacks
    5. User-defined transfer functions
    """
    
    @property
    def name(self) -> str:
        return "Cross-Contract Reentrancy Detector"
    
    @property
    def description(self) -> str:
        return (
            "Detects reentrancy vulnerabilities arising from cross-contract "
            "interactions, including ERC token hooks, flash loan callbacks, "
            "and custom interface implementations that can be exploited for "
            "reentrancy attacks."
        )
    
    @property
    def reentrancy_type(self) -> ReentrancyType:
        return ReentrancyType.CROSS_CONTRACT
    
    # Known dangerous callback patterns
    DANGEROUS_CALLBACKS = {
        # ERC777 hooks
        'tokensReceived': {
            'severity': Severity.HIGH,
            'description': 'ERC777 token receive hook - can be exploited for reentrancy',
        },
        'tokensToSend': {
            'severity': Severity.HIGH,
            'description': 'ERC777 token send hook - can trigger reentrancy',
        },
        # ERC721 hooks
        'onERC721Received': {
            'severity': Severity.MEDIUM,
            'description': 'ERC721 safe transfer hook - potential reentrancy vector',
        },
        # ERC1155 hooks
        'onERC1155Received': {
            'severity': Severity.MEDIUM,
            'description': 'ERC1155 receive hook - potential reentrancy vector',
        },
        'onERC1155BatchReceived': {
            'severity': Severity.MEDIUM,
            'description': 'ERC1155 batch receive hook - potential reentrancy vector',
        },
        # Flash loan callbacks
        'onFlashLoan': {
            'severity': Severity.HIGH,
            'description': 'Flash loan callback - common reentrancy attack vector',
        },
        'executeOperation': {
            'severity': Severity.HIGH,
            'description': 'Aave flash loan callback - must be protected',
        },
        'uniswapV2Call': {
            'severity': Severity.HIGH,
            'description': 'Uniswap V2 flash swap callback',
        },
        'uniswapV3FlashCallback': {
            'severity': Severity.HIGH,
            'description': 'Uniswap V3 flash callback',
        },
        'pancakeCall': {
            'severity': Severity.HIGH,
            'description': 'PancakeSwap flash swap callback',
        },
    }
    
    # Patterns indicating external contract calls with user input
    USER_CONTROLLED_CALL_PATTERNS = [
        r'(\w+)\.(\w+)\s*\(',  # contract.function()
        r'I\w+\s*\(\s*(\w+)\s*\)\s*\.\s*(\w+)',  # IInterface(addr).function()
        r'address\s*\(\s*(\w+)\s*\)\s*\.call',  # address(var).call
    ]
    
    def analyze(self, contract_path: Path) -> List[ReentrancyVulnerability]:
        """
        Analyze a contract for cross-contract reentrancy vulnerabilities.
        """
        vulnerabilities = []
        
        with open(contract_path, 'r') as f:
            source_code = f.read()
        
        has_oz_guard = self.check_openzeppelin_guard(source_code)
        
        # Check for dangerous callback implementations
        callback_vulns = self._check_callback_implementations(
            source_code, str(contract_path), has_oz_guard
        )
        vulnerabilities.extend(callback_vulns)
        
        # Check for user-controlled external calls
        external_call_vulns = self._check_user_controlled_calls(
            source_code, str(contract_path), has_oz_guard
        )
        vulnerabilities.extend(external_call_vulns)
        
        # Check for unsafe token interactions
        token_vulns = self._check_token_interactions(
            source_code, str(contract_path), has_oz_guard
        )
        vulnerabilities.extend(token_vulns)
        
        return vulnerabilities
    
    def analyze_bytecode(self, bytecode: str) -> List[ReentrancyVulnerability]:
        """
        Bytecode analysis for cross-contract reentrancy.
        
        Looks for:
        - Function selectors of known callbacks
        - CALL opcodes with dynamic targets
        """
        vulnerabilities = []
        
        if bytecode.startswith('0x'):
            bytecode = bytecode[2:]
        
        # Known callback function selectors
        callback_selectors = {
            '0023de29': 'tokensReceived',
            '75ab9782': 'tokensToSend', 
            '150b7a02': 'onERC721Received',
            'f23a6e61': 'onERC1155Received',
            'bc197c81': 'onERC1155BatchReceived',
        }
        
        for selector, callback_name in callback_selectors.items():
            if selector in bytecode.lower():
                vuln = ReentrancyVulnerability(
                    id=str(uuid.uuid4()),
                    type=ReentrancyType.CROSS_CONTRACT,
                    severity=Severity.MEDIUM,
                    title=f"Callback Implementation Detected: {callback_name}",
                    description=(
                        f"The bytecode contains the function selector for "
                        f"'{callback_name}'. This callback can be exploited "
                        f"for cross-contract reentrancy attacks."
                    ),
                    location=VulnerabilityLocation(
                        file_path="bytecode",
                        contract_name="Unknown",
                        function_name=callback_name,
                        line_start=0,
                        line_end=0,
                    ),
                    attack_vector=(
                        "An attacker can deploy a contract that triggers this "
                        "callback during a token transfer, re-entering the "
                        "victim contract before state updates complete."
                    ),
                    recommendation=(
                        "Ensure the callback implementation follows CEI pattern "
                        "and uses reentrancy guards where appropriate."
                    ),
                    confidence=0.6,
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_callback_implementations(
        self,
        source_code: str,
        contract_path: str,
        has_oz_guard: bool,
    ) -> List[ReentrancyVulnerability]:
        """Check for dangerous callback function implementations."""
        vulnerabilities = []
        
        for callback_name, info in self.DANGEROUS_CALLBACKS.items():
            # Look for function definition
            pattern = rf'function\s+{callback_name}\s*\([^)]*\)[^{{]*\{{([^}}]*(?:\{{[^}}]*\}}[^}}]*)*)\}}'
            match = re.search(pattern, source_code, re.DOTALL)
            
            if match:
                func_body = match.group(1)
                start_line = source_code[:match.start()].count('\n') + 1
                
                # Check if it has protection
                has_protection = bool(re.search(
                    r'nonReentrant|mutex|locked', 
                    match.group(0), 
                    re.IGNORECASE
                ))
                
                # Check if it makes state changes
                makes_state_changes = bool(re.search(
                    r'\w+\s*\[[^\]]+\]\s*[+\-]?=|\.transfer\(|\.call\{',
                    func_body
                ))
                
                if makes_state_changes and not has_protection:
                    vuln = ReentrancyVulnerability(
                        id=str(uuid.uuid4()),
                        type=ReentrancyType.CROSS_CONTRACT,
                        severity=info['severity'],
                        title=f"Unprotected Callback: {callback_name}()",
                        description=(
                            f"{info['description']}. The implementation modifies "
                            f"state without reentrancy protection."
                        ),
                        location=VulnerabilityLocation(
                            file_path=contract_path,
                            contract_name="Unknown",
                            function_name=callback_name,
                            line_start=start_line,
                            line_end=start_line + match.group(0).count('\n'),
                        ),
                        attack_vector=(
                            f"1. Attacker initiates token transfer to victim contract\n"
                            f"2. Token contract calls {callback_name}() on victim\n"
                            f"3. Attacker's contract receives callback and re-enters\n"
                            f"4. State is manipulated before original call completes"
                        ),
                        recommendation=(
                            f"1. Add nonReentrant modifier to {callback_name}()\n"
                            f"2. Follow Checks-Effects-Interactions pattern\n"
                            f"3. Be cautious when accepting ERC777/ERC721/ERC1155 tokens\n"
                            f"4. Consider using ERC20 instead of ERC777 if hooks aren't needed"
                        ),
                        confidence=0.8,
                        has_reentrancy_guard=has_oz_guard,
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_user_controlled_calls(
        self,
        source_code: str,
        contract_path: str,
        has_oz_guard: bool,
    ) -> List[ReentrancyVulnerability]:
        """Check for external calls to user-controlled addresses."""
        vulnerabilities = []
        
        # Find functions with external calls to parameters
        functions = extract_solidity_functions(source_code)
        
        for func_name, func_info in functions.items():
            params = func_info['params']
            func_body = func_info['body']
            
            # Extract address parameters
            addr_params = re.findall(r'address\s+(\w+)', params)
            
            for param in addr_params:
                # Check if this address is used for external calls
                call_patterns = [
                    rf'{param}\s*\.\s*\w+\s*\(',  # param.function()
                    rf'I\w+\s*\(\s*{param}\s*\)',  # IInterface(param)
                    rf'address\s*\(\s*{param}\s*\)\s*\.call',  # address(param).call
                ]
                
                for pattern in call_patterns:
                    if re.search(pattern, func_body):
                        # Check for protection
                        has_protection = bool(re.search(
                            r'nonReentrant', func_info['code'], re.IGNORECASE
                        ))
                        
                        if not has_protection:
                            start_line = func_info['start_line']
                            
                            vuln = ReentrancyVulnerability(
                                id=str(uuid.uuid4()),
                                type=ReentrancyType.CROSS_CONTRACT,
                                severity=Severity.HIGH,
                                title=f"User-Controlled External Call in {func_name}()",
                                description=(
                                    f"Function '{func_name}()' makes an external call "
                                    f"to a user-supplied address '{param}'. This allows "
                                    f"attackers to specify a malicious contract that "
                                    f"re-enters during the call."
                                ),
                                location=VulnerabilityLocation(
                                    file_path=contract_path,
                                    contract_name="Unknown",
                                    function_name=func_name,
                                    line_start=start_line,
                                    line_end=start_line + func_info['code'].count('\n'),
                                ),
                                attack_vector=(
                                    f"1. Attacker calls {func_name}() with malicious contract address\n"
                                    f"2. Function makes external call to attacker's contract\n"
                                    f"3. Attacker's contract re-enters victim\n"
                                    f"4. State manipulation occurs before original call completes"
                                ),
                                recommendation=(
                                    "1. Add nonReentrant modifier\n"
                                    "2. Validate external addresses against whitelist\n"
                                    "3. Follow CEI pattern strictly\n"
                                    "4. Consider using pull-over-push pattern"
                                ),
                                confidence=0.7,
                                has_reentrancy_guard=has_oz_guard,
                            )
                            vulnerabilities.append(vuln)
                        break
        
        return vulnerabilities
    
    def _check_token_interactions(
        self,
        source_code: str,
        contract_path: str,
        has_oz_guard: bool,
    ) -> List[ReentrancyVulnerability]:
        """Check for unsafe token transfer patterns."""
        vulnerabilities = []
        
        # Dangerous patterns with ERC777/ERC721
        dangerous_patterns = [
            {
                'pattern': r'safeTransferFrom\s*\([^)]+\)',
                'token_type': 'ERC721/ERC1155',
                'risk': 'Safe transfer triggers onERC721Received callback',
            },
            {
                'pattern': r'IERC777\s*\([^)]+\)\s*\.\s*send\s*\(',
                'token_type': 'ERC777',
                'risk': 'ERC777 send triggers tokensToSend and tokensReceived hooks',
            },
            {
                'pattern': r'\.safeTransfer\s*\([^)]+\)',
                'token_type': 'ERC721/ERC1155',
                'risk': 'Safe transfer can trigger receiver callbacks',
            },
        ]
        
        for dp in dangerous_patterns:
            for match in re.finditer(dp['pattern'], source_code):
                # Find the enclosing function
                func_match = self._find_enclosing_function(source_code, match.start())
                
                if func_match:
                    func_code = func_match['code']
                    has_protection = bool(re.search(
                        r'nonReentrant', func_code, re.IGNORECASE
                    ))
                    
                    if not has_protection:
                        start_line = source_code[:match.start()].count('\n') + 1
                        
                        vuln = ReentrancyVulnerability(
                            id=str(uuid.uuid4()),
                            type=ReentrancyType.CROSS_CONTRACT,
                            severity=Severity.MEDIUM,
                            title=f"Unsafe {dp['token_type']} Transfer Pattern",
                            description=(
                                f"{dp['risk']}. Without reentrancy protection, "
                                f"this can be exploited for cross-contract reentrancy."
                            ),
                            location=VulnerabilityLocation(
                                file_path=contract_path,
                                contract_name="Unknown",
                                function_name="Unknown",
                                line_start=start_line,
                                line_end=start_line,
                                source_snippet=match.group(0),
                            ),
                            attack_vector=(
                                f"1. Attacker deploys contract implementing token receiver\n"
                                f"2. Token transfer triggers callback to attacker\n"
                                f"3. Attacker re-enters victim contract\n"
                                f"4. Exploits inconsistent state"
                            ),
                            recommendation=(
                                "1. Use nonReentrant modifier on functions with token transfers\n"
                                "2. Update state before token transfers\n"
                                "3. Consider using transferFrom instead of safeTransferFrom "
                                "if callbacks aren't needed"
                            ),
                            confidence=0.65,
                            has_reentrancy_guard=has_oz_guard,
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _find_enclosing_function(self, source_code: str, position: int):
        """Find the function that contains the given position."""
        for func_info in extract_solidity_functions(source_code).values():
            start = source_code.find(func_info['code'])
            if start != -1 and start <= position <= start + len(func_info['code']):
                return func_info
        
        return None
