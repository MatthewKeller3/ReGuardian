"""
Read-Only Reentrancy Detector

Detects read-only reentrancy vulnerabilities where view functions
return stale/manipulated data during an external call.

Notable example: Curve Finance attack (initially thought to be read-only reentrancy)
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


class ReadOnlyReentrancyDetector(ReentrancyDetector):
    """
    Detector for read-only reentrancy vulnerabilities.
    
    This type of reentrancy exploits view functions that:
    1. Are called by other protocols for pricing/state information
    2. Return values based on state that can be manipulated mid-transaction
    3. Don't have reentrancy protection (since they're "read-only")
    
    Common in:
    - LP token pricing
    - Oracle implementations
    - Collateral calculations
    """
    
    @property
    def name(self) -> str:
        return "Read-Only Reentrancy Detector"
    
    @property
    def description(self) -> str:
        return (
            "Detects read-only reentrancy vulnerabilities where view functions "
            "can return manipulated values during an external call, affecting "
            "dependent protocols that rely on these values for pricing or "
            "collateral calculations."
        )
    
    @property
    def reentrancy_type(self) -> ReentrancyType:
        return ReentrancyType.READ_ONLY
    
    # Patterns for view functions that might be exploitable
    PRICING_FUNCTION_PATTERNS = [
        r'getPrice',
        r'get.*Price',
        r'get.*Rate',
        r'get.*Value',
        r'totalAssets',
        r'totalSupply',
        r'balanceOf',
        r'getReserves',
        r'get.*Balance',
        r'convertToAssets',
        r'convertToShares',
        r'previewDeposit',
        r'previewWithdraw',
        r'previewMint',
        r'previewRedeem',
        r'exchangeRate',
    ]
    
    def analyze(self, contract_path: Path) -> List[ReentrancyVulnerability]:
        """
        Analyze a contract for read-only reentrancy vulnerabilities.
        """
        vulnerabilities = []
        
        with open(contract_path, 'r') as f:
            source_code = f.read()
        
        has_oz_guard = self.check_openzeppelin_guard(source_code)
        
        # Find view functions that could be exploited
        view_functions = self._find_view_functions(source_code)
        
        # Find functions with external calls
        external_call_functions = self._find_external_call_functions(source_code)
        
        # Check for vulnerable patterns
        for view_func in view_functions:
            # Check if any external call function modifies state used by this view
            for ext_func in external_call_functions:
                if self._shares_state(view_func, ext_func):
                    vuln = self._create_vulnerability(
                        view_func=view_func,
                        ext_func=ext_func,
                        contract_path=str(contract_path),
                        has_oz_guard=has_oz_guard,
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
        
        # Check for specific vulnerable patterns
        pattern_vulns = self._check_vulnerable_patterns(
            source_code, str(contract_path), has_oz_guard
        )
        vulnerabilities.extend(pattern_vulns)
        
        return vulnerabilities
    
    def analyze_bytecode(self, bytecode: str) -> List[ReentrancyVulnerability]:
        """
        Bytecode analysis for read-only reentrancy.
        
        Looks for:
        - STATICCALL followed by SLOAD patterns
        - View function selectors with state dependencies
        """
        # Read-only reentrancy is difficult to detect from bytecode alone
        # as it requires understanding cross-contract dependencies
        return []
    
    def _find_view_functions(self, source_code: str) -> List[Dict[str, Any]]:
        """Find view/pure functions that might be exploitable."""
        view_functions = []
        
        for func_name, func_info in extract_solidity_functions(source_code).items():
            # Only consider view/pure functions
            if not re.search(r'\b(view|pure)\b', func_info['modifiers']):
                continue
            
            func_body = func_info['body']
            
            # Check if it's a pricing-related function
            is_pricing = any(
                re.search(p, func_name, re.IGNORECASE) 
                for p in self.PRICING_FUNCTION_PATTERNS
            )
            
            # Find state variables read
            state_reads = self._extract_state_reads(func_body)
            
            view_functions.append({
                'name': func_name,
                'code': func_info['code'],
                'body': func_body,
                'start_line': func_info['start_line'],
                'is_pricing': is_pricing,
                'state_reads': state_reads,
            })
        
        return view_functions
    
    def _find_external_call_functions(self, source_code: str) -> List[Dict[str, Any]]:
        """Find functions that make external calls."""
        external_functions = []
        
        for func_name, func_info in extract_solidity_functions(source_code).items():
            func_body = func_info['body']
            
            # Check for external calls
            has_external_call = bool(re.search(
                r'\.call\s*[\({]|\.send\s*\(|\.transfer\s*\(|\.delegatecall\s*\(',
                func_body
            ))
            
            if has_external_call:
                # Find state variables written
                state_writes = self._extract_state_writes(func_body)
                
                external_functions.append({
                    'name': func_name,
                    'code': func_info['code'],
                    'body': func_body,
                    'start_line': func_info['start_line'],
                    'state_writes': state_writes,
                })
        
        return external_functions
    
    def _extract_state_reads(self, func_body: str) -> Set[str]:
        """Extract state variables read in function body."""
        reads = set()
        
        # Common patterns for state reads
        patterns = [
            r'\b(\w+)\s*\[',  # mapping access
            r'\b(total\w+)\b',  # totalSupply, totalAssets, etc.
            r'\b(balance\w*)\b',  # balance variables
            r'\b(reserve\w*)\b',  # reserve variables
            r'\b(_\w+)\b',  # private variables with underscore
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, func_body):
                reads.add(match.group(1))
        
        return reads
    
    def _extract_state_writes(self, func_body: str) -> Set[str]:
        """Extract state variables written in function body."""
        writes = set()
        
        patterns = [
            r'(\w+)\s*\[[^\]]+\]\s*[+\-\*\/]?=',
            r'(\w+)\s*[+\-\*\/]?=\s*[^=]',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, func_body):
                writes.add(match.group(1))
        
        return writes
    
    def _shares_state(
        self, 
        view_func: Dict[str, Any], 
        ext_func: Dict[str, Any]
    ) -> bool:
        """Check if view function reads state that external function writes."""
        return bool(view_func['state_reads'] & ext_func['state_writes'])
    
    def _create_vulnerability(
        self,
        view_func: Dict[str, Any],
        ext_func: Dict[str, Any],
        contract_path: str,
        has_oz_guard: bool,
    ) -> ReentrancyVulnerability:
        """Create vulnerability for read-only reentrancy."""
        
        shared_state = view_func['state_reads'] & ext_func['state_writes']
        
        # Higher severity for pricing functions
        severity = Severity.HIGH if view_func['is_pricing'] else Severity.MEDIUM
        
        return ReentrancyVulnerability(
            id=str(uuid.uuid4()),
            type=ReentrancyType.READ_ONLY,
            severity=severity,
            title=f"Read-Only Reentrancy: {view_func['name']}() ↔ {ext_func['name']}()",
            description=(
                f"The view function '{view_func['name']}()' reads state variables "
                f"({', '.join(shared_state)}) that are modified by '{ext_func['name']}()' "
                f"which makes external calls. During the external call, other protocols "
                f"calling '{view_func['name']}()' will receive stale/manipulated values."
            ),
            location=VulnerabilityLocation(
                file_path=contract_path,
                contract_name="Unknown",
                function_name=view_func['name'],
                line_start=view_func['start_line'],
                line_end=view_func['start_line'] + view_func['code'].count('\n'),
            ),
            attack_vector=(
                f"1. Attacker calls {ext_func['name']}() which makes external call\n"
                f"2. During callback, attacker interacts with dependent protocol\n"
                f"3. Dependent protocol calls {view_func['name']}() for pricing\n"
                f"4. Returns stale value (state not yet updated)\n"
                f"5. Attacker exploits price discrepancy"
            ),
            recommendation=(
                "1. Update state BEFORE external calls (CEI pattern)\n"
                "2. Consider adding reentrancy locks to view functions\n"
                "3. Use snapshot-based pricing that caches values\n"
                "4. Implement time-weighted average prices (TWAP)\n"
                "5. Add staleness checks to dependent protocols"
            ),
            references=[
                "https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/",
                "https://blog.openzeppelin.com/read-only-reentrancy-vulnerability",
            ],
            confidence=0.7,
            has_reentrancy_guard=has_oz_guard,
            suggested_fix=self._generate_fix(view_func['name'], ext_func['name']),
        )
    
    def _check_vulnerable_patterns(
        self,
        source_code: str,
        contract_path: str,
        has_oz_guard: bool,
    ) -> List[ReentrancyVulnerability]:
        """Check for specific vulnerable patterns."""
        vulnerabilities = []
        
        # Pattern 1: LP token price calculation with external calls
        lp_pattern = r'function\s+(\w*[Pp]rice\w*|\w*[Rr]ate\w*)\s*\([^)]*\)[^{]*view[^{]*\{[^}]*(?:totalSupply|getReserves|balance)[^}]*\}'
        
        for match in re.finditer(lp_pattern, source_code, re.DOTALL):
            func_name = match.group(1)
            start_line = source_code[:match.start()].count('\n') + 1
            
            vuln = ReentrancyVulnerability(
                id=str(uuid.uuid4()),
                type=ReentrancyType.READ_ONLY,
                severity=Severity.MEDIUM,
                title=f"Potential LP Price Manipulation: {func_name}()",
                description=(
                    f"The function '{func_name}()' calculates price based on "
                    f"reserve/supply ratios. These values can be manipulated "
                    f"during reentrancy, leading to incorrect pricing."
                ),
                location=VulnerabilityLocation(
                    file_path=contract_path,
                    contract_name="Unknown",
                    function_name=func_name,
                    line_start=start_line,
                    line_end=start_line + match.group(0).count('\n'),
                ),
                attack_vector=(
                    "1. Attacker manipulates reserves via flash loan or reentrancy\n"
                    "2. Price function returns manipulated value\n"
                    "3. Dependent protocol uses incorrect price\n"
                    "4. Attacker profits from price discrepancy"
                ),
                recommendation=(
                    "1. Use time-weighted average prices (TWAP)\n"
                    "2. Add manipulation resistance checks\n"
                    "3. Consider using Chainlink or other oracles\n"
                    "4. Implement price deviation limits"
                ),
                confidence=0.6,
                has_reentrancy_guard=has_oz_guard,
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _generate_fix(self, view_func: str, ext_func: str) -> str:
        """Generate fix suggestion for read-only reentrancy."""
        return f"""
// Option 1: Update state before external calls
function {ext_func}() external nonReentrant {{
    // 1. Update all state variables FIRST
    _updateReserves();
    _updatePricing();
    
    // 2. Make external calls LAST
    (bool success, ) = recipient.call{{value: amount}}("");
    require(success);
}}

// Option 2: Use cached/snapshot values for pricing
uint256 private _cachedPrice;
uint256 private _lastPriceUpdate;

function {view_func}() public view returns (uint256) {{
    // Return cached value if within acceptable staleness
    if (block.timestamp - _lastPriceUpdate < MAX_STALENESS) {{
        return _cachedPrice;
    }}
    // Otherwise calculate fresh (but be aware of manipulation)
    return _calculatePrice();
}}

// Option 3: Add reentrancy check to view function
uint256 private _status;
uint256 private constant _NOT_ENTERED = 1;
uint256 private constant _ENTERED = 2;

function {view_func}() public view returns (uint256) {{
    // Revert if called during reentrancy
    require(_status != _ENTERED, "ReentrancyGuard: view reentrant call");
    return _calculatePrice();
}}
"""
