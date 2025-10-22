"""
Unit tests for AI agents
"""
import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch

from src.agents.log_analysis_agent import LogAnalysisAgent
from src.agents.file_analysis_agent import FileAnalysisAgent
from src.agents.network_analysis_agent import NetworkAnalysisAgent
from src.agents.correlation_agent import CorrelationAgent
from src.models.evidence import Evidence, EvidenceType


@pytest.fixture
def mock_llm_client():
    """Mock LLM client for testing"""
    mock = AsyncMock()
    mock.invoke = AsyncMock(return_value=Mock(
        content='{"findings": [], "confidence": 0.8, "reasoning": "Test analysis"}'
    ))
    return mock


@pytest.fixture
def sample_log_evidence():
    """Create sample log evidence for testing"""
    return [
        Evidence(
            evidence_id="EVD-001",
            evidence_type=EvidenceType.LOG,
            source_path="/var/log/auth.log",
            hash="abc123",
            collected_at=datetime.now(),
            data="Failed password for admin from 192.168.1.100\nFailed password for admin from 192.168.1.100\nAccepted password for admin from 192.168.1.100",
            metadata={"line_count": 3}
        )
    ]


@pytest.fixture
def sample_file_evidence():
    """Create sample file evidence for testing"""
    return [
        Evidence(
            evidence_id="EVD-002",
            evidence_type=EvidenceType.FILE_METADATA,
            source_path="/tmp/suspicious.exe",
            hash="def456",
            collected_at=datetime.now(),
            data="",
            metadata={
                "extension": ".exe",
                "size": 1024000,
                "suspicious": True
            }
        )
    ]


@pytest.fixture
def sample_network_evidence():
    """Create sample network evidence for testing"""
    return [
        Evidence(
            evidence_id="EVD-003",
            evidence_type=EvidenceType.NETWORK_TRAFFIC,
            source_path="/var/log/network.log",
            hash="ghi789",
            collected_at=datetime.now(),
            data="192.168.1.100,8.8.8.8,443,beaconing_pattern",
            metadata={
                "connection_count": 100,
                "protocols": ["TCP"]
            }
        )
    ]


class TestLogAnalysisAgent:
    """Test suite for LogAnalysisAgent"""
    
    @pytest.mark.asyncio
    async def test_agent_initialization(self, mock_llm_client):
        """Test agent can be initialized"""
        agent = LogAnalysisAgent(mock_llm_client)
        assert agent is not None
        assert agent.name == "LogAnalysisAgent"
    
    @pytest.mark.asyncio
    async def test_analyze_logs(self, mock_llm_client, sample_log_evidence):
        """Test log analysis"""
        agent = LogAnalysisAgent(mock_llm_client)
        result = await agent.analyze(sample_log_evidence)
        
        assert result is not None
        assert 'findings' in result
        assert 'confidence' in result
        assert 'agent_name' in result
    
    @pytest.mark.asyncio
    async def test_brute_force_detection(self, mock_llm_client, sample_log_evidence):
        """Test detection of brute force attacks"""
        # Mock LLM to return brute force finding
        mock_llm_client.invoke = AsyncMock(return_value=Mock(
            content='{"findings": [{"type": "brute_force", "severity": "high", "description": "Multiple failed login attempts"}], "confidence": 0.9}'
        ))
        
        agent = LogAnalysisAgent(mock_llm_client)
        result = await agent.analyze(sample_log_evidence)
        
        assert len(result['findings']) > 0
        assert result['confidence'] >= 0.7


class TestFileAnalysisAgent:
    """Test suite for FileAnalysisAgent"""
    
    @pytest.mark.asyncio
    async def test_agent_initialization(self, mock_llm_client):
        """Test agent can be initialized"""
        agent = FileAnalysisAgent(mock_llm_client)
        assert agent is not None
        assert agent.name == "FileAnalysisAgent"
    
    @pytest.mark.asyncio
    async def test_analyze_files(self, mock_llm_client, sample_file_evidence):
        """Test file analysis"""
        agent = FileAnalysisAgent(mock_llm_client)
        result = await agent.analyze(sample_file_evidence)
        
        assert result is not None
        assert 'findings' in result
        assert 'agent_name' in result
    
    @pytest.mark.asyncio
    async def test_malware_detection(self, mock_llm_client, sample_file_evidence):
        """Test malware detection in files"""
        # Mock LLM to return malware finding
        mock_llm_client.invoke = AsyncMock(return_value=Mock(
            content='{"findings": [{"type": "malware", "severity": "critical", "description": "Suspicious executable detected"}], "confidence": 0.95}'
        ))
        
        agent = FileAnalysisAgent(mock_llm_client)
        result = await agent.analyze(sample_file_evidence)
        
        assert len(result['findings']) > 0
        assert result['confidence'] >= 0.9


class TestNetworkAnalysisAgent:
    """Test suite for NetworkAnalysisAgent"""
    
    @pytest.mark.asyncio
    async def test_agent_initialization(self, mock_llm_client):
        """Test agent can be initialized"""
        agent = NetworkAnalysisAgent(mock_llm_client)
        assert agent is not None
        assert agent.name == "NetworkAnalysisAgent"
    
    @pytest.mark.asyncio
    async def test_analyze_network(self, mock_llm_client, sample_network_evidence):
        """Test network analysis"""
        agent = NetworkAnalysisAgent(mock_llm_client)
        result = await agent.analyze(sample_network_evidence)
        
        assert result is not None
        assert 'findings' in result
        assert 'agent_name' in result
    
    @pytest.mark.asyncio
    async def test_c2_detection(self, mock_llm_client, sample_network_evidence):
        """Test C2 beaconing detection"""
        # Mock LLM to return C2 finding
        mock_llm_client.invoke = AsyncMock(return_value=Mock(
            content='{"findings": [{"type": "c2_communication", "severity": "critical", "description": "Beaconing pattern detected"}], "confidence": 0.92}'
        ))
        
        agent = NetworkAnalysisAgent(mock_llm_client)
        result = await agent.analyze(sample_network_evidence)
        
        assert len(result['findings']) > 0


class TestCorrelationAgent:
    """Test suite for CorrelationAgent"""
    
    @pytest.mark.asyncio
    async def test_agent_initialization(self, mock_llm_client):
        """Test agent can be initialized"""
        agent = CorrelationAgent(mock_llm_client)
        assert agent is not None
        assert agent.name == "CorrelationAgent"
    
    @pytest.mark.asyncio
    async def test_correlate_findings(self, mock_llm_client):
        """Test correlation of findings from multiple agents"""
        # Create mock findings from different agents
        all_findings = {
            'log_findings': [
                {'type': 'brute_force', 'timestamp': '2024-10-21 10:00:00'}
            ],
            'file_findings': [
                {'type': 'malware', 'timestamp': '2024-10-21 10:05:00'}
            ],
            'network_findings': [
                {'type': 'c2_communication', 'timestamp': '2024-10-21 10:10:00'}
            ]
        }
        
        # Mock LLM to return correlated timeline
        mock_llm_client.invoke = AsyncMock(return_value=Mock(
            content='{"timeline": [{"event": "Initial access via brute force", "timestamp": "2024-10-21 10:00:00"}], "attack_chain": "credential_access -> execution -> command_and_control"}'
        ))
        
        agent = CorrelationAgent(mock_llm_client)
        result = await agent.correlate(all_findings)
        
        assert result is not None
        assert 'timeline' in result or 'attack_chain' in result


class TestAgentIntegration:
    """Integration tests for multi-agent workflows"""
    
    @pytest.mark.asyncio
    async def test_multi_agent_analysis(self, mock_llm_client, sample_log_evidence, 
                                        sample_file_evidence, sample_network_evidence):
        """Test multiple agents analyzing different evidence types"""
        log_agent = LogAnalysisAgent(mock_llm_client)
        file_agent = FileAnalysisAgent(mock_llm_client)
        network_agent = NetworkAnalysisAgent(mock_llm_client)
        
        # Run all agents
        log_results = await log_agent.analyze(sample_log_evidence)
        file_results = await file_agent.analyze(sample_file_evidence)
        network_results = await network_agent.analyze(sample_network_evidence)
        
        # All should complete successfully
        assert log_results is not None
        assert file_results is not None
        assert network_results is not None
    
    @pytest.mark.asyncio
    async def test_agent_error_handling(self, mock_llm_client, sample_log_evidence):
        """Test agent error handling when LLM fails"""
        # Mock LLM to raise an exception
        mock_llm_client.invoke = AsyncMock(side_effect=Exception("API Error"))
        
        agent = LogAnalysisAgent(mock_llm_client)
        
        # Agent should handle the error gracefully
        with pytest.raises(Exception):
            await agent.analyze(sample_log_evidence)
    
    @pytest.mark.asyncio
    async def test_confidence_scoring(self, mock_llm_client, sample_log_evidence):
        """Test confidence score validation"""
        # Mock various confidence levels
        test_cases = [
            ('{"findings": [], "confidence": 0.5}', 0.5),
            ('{"findings": [], "confidence": 0.9}', 0.9),
            ('{"findings": [], "confidence": 1.0}', 1.0),
        ]
        
        agent = LogAnalysisAgent(mock_llm_client)
        
        for response_content, expected_confidence in test_cases:
            mock_llm_client.invoke = AsyncMock(return_value=Mock(
                content=response_content
            ))
            
            result = await agent.analyze(sample_log_evidence)
            assert result['confidence'] == expected_confidence


if __name__ == "__main__":
    pytest.main([__file__, "-v"])