"""
Fix Agent Constructors - Updates all agents to accept llm_client parameter
Run this from your project root directory
"""
import os
import re
from pathlib import Path


def fix_log_analysis_agent():
    """Fix LogAnalysisAgent constructor"""
    filepath = Path('src/agents/log_analysis_agent.py')
    
    if not filepath.exists():
        print(f"✗ File not found: {filepath}")
        return False
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if already has llm_client parameter
        if 'def __init__(self, llm_client=None):' in content:
            print(f"  Skipped: {filepath} (already fixed)")
            return False
        
        # Replace old constructor
        old_pattern = r'def __init__\(self\):'
        new_constructor = '''def __init__(self, llm_client=None):
        super().__init__(
            agent_name="LogAnalysisAgent",
            agent_description="Analyzes system and application logs for security events",
            llm_client=llm_client
        )'''
        
        content = re.sub(
            r'def __init__\(self\):.*?super\(\).__init__\([^)]*\)',
            new_constructor,
            content,
            flags=re.DOTALL
        )
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✓ Fixed: {filepath}")
        return True
        
    except Exception as e:
        print(f"✗ Error fixing {filepath}: {e}")
        return False


def fix_network_analysis_agent():
    """Fix NetworkAnalysisAgent constructor"""
    filepath = Path('src/agents/network_analysis_agent.py')
    
    if not filepath.exists():
        print(f"✗ File not found: {filepath}")
        return False
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if already has llm_client parameter
        if 'def __init__(self, llm_client=None):' in content:
            print(f"  Skipped: {filepath} (already fixed)")
            return False
        
        # Replace old constructor
        old_pattern = r'def __init__\(self\):'
        new_constructor = '''def __init__(self, llm_client=None):
        super().__init__(
            agent_name="NetworkAnalysisAgent",
            agent_description="Analyzes network traffic and connection patterns",
            llm_client=llm_client
        )'''
        
        content = re.sub(
            r'def __init__\(self\):.*?super\(\).__init__\([^)]*\)',
            new_constructor,
            content,
            flags=re.DOTALL
        )
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✓ Fixed: {filepath}")
        return True
        
    except Exception as e:
        print(f"✗ Error fixing {filepath}: {e}")
        return False


def add_missing_methods_if_needed(filepath):
    """Add add_finding and clear_findings methods if missing"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if methods already exist
        if 'def add_finding(self' in content and 'def clear_findings(self' in content:
            return False
        
        # Find the last method or end of class
        methods_to_add = '''
    
    def add_finding(self, finding):
        """Add a finding to the agent's findings list"""
        if not hasattr(self, 'findings'):
            self.findings = []
        if hasattr(finding, 'to_dict'):
            self.findings.append(finding.to_dict())
        else:
            self.findings.append(finding)
    
    def clear_findings(self):
        """Clear all findings"""
        if not hasattr(self, 'findings'):
            self.findings = []
        else:
            self.findings.clear()
'''
        
        # Add before the last line of the file (usually just whitespace)
        lines = content.split('\n')
        
        # Find where to insert (before last non-empty line or end of class)
        insert_pos = len(lines)
        for i in range(len(lines) - 1, -1, -1):
            if lines[i].strip() and not lines[i].strip().startswith('#'):
                insert_pos = i + 1
                break
        
        lines.insert(insert_pos, methods_to_add)
        content = '\n'.join(lines)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✓ Added missing methods to: {filepath}")
        return True
        
    except Exception as e:
        print(f"✗ Error adding methods to {filepath}: {e}")
        return False


def main():
    """Fix all agent constructors"""
    print("=" * 70)
    print("AGENT CONSTRUCTOR FIXER")
    print("=" * 70)
    print()
    
    fixed_count = 0
    
    # Fix LogAnalysisAgent
    print("Checking LogAnalysisAgent...")
    if fix_log_analysis_agent():
        fixed_count += 1
    
    # Fix NetworkAnalysisAgent
    print("Checking NetworkAnalysisAgent...")
    if fix_network_analysis_agent():
        fixed_count += 1
    
    # Add missing methods to all agents
    print("\nChecking for missing methods...")
    agent_files = [
        'src/agents/log_analysis_agent.py',
        'src/agents/network_analysis_agent.py',
        'src/agents/file_analysis_agent.py',
        'src/agents/correlation_agent.py'
    ]
    
    for agent_file in agent_files:
        filepath = Path(agent_file)
        if filepath.exists():
            if add_missing_methods_if_needed(filepath):
                fixed_count += 1
    
    print()
    print("=" * 70)
    print(f"SUMMARY: Fixed {fixed_count} agent(s)")
    print("=" * 70)
    print()
    
    if fixed_count > 0:
        print("✅ Agent constructors fixed successfully!")
        print("   You can now run: python main.py --mode demo")
    else:
        print("ℹ️  All agents already have correct constructors.")


if __name__ == '__main__':
    main()