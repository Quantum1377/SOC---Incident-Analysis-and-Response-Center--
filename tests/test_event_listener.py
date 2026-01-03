import pytest
import asyncio
from unittest.mock import AsyncMock, patch, call
import logging
from event_listener import listen_to_bus, EVENT_BUS_HOST, EVENT_BUS_PORT, CLIENT_NAME

@pytest.mark.asyncio
@patch('asyncio.open_connection')
async def test_listen_to_bus_success_and_messages(mock_open_connection, caplog):
    """Test successful connection and message reception by listen_to_bus."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_writer = AsyncMock(spec=asyncio.StreamWriter)
    
    # Mock is_closing to return False so that close() is called
    mock_writer.is_closing.return_value = False

    mock_open_connection.return_value = (mock_reader, mock_writer)

    mock_reader.readline.side_effect = [
        b"message 1\n",
        b"message 2\n",
        b"" # EOF to simulate disconnect
    ]

    with caplog.at_level(logging.INFO):
        await listen_to_bus()

        mock_open_connection.assert_called_once_with(EVENT_BUS_HOST, EVENT_BUS_PORT)
        mock_reader.readline.assert_has_calls([call(), call(), call()])
        
        assert f"Connected to event bus at {EVENT_BUS_HOST}:{EVENT_BUS_PORT}" in caplog.text
        assert "Received from bus: message 1" in caplog.text
        assert "Received from bus: message 2" in caplog.text
        assert "Disconnected from event bus." in caplog.text
        
        mock_writer.close.assert_called_once()
        mock_writer.wait_closed.assert_called_once()

@pytest.mark.asyncio
@patch('asyncio.open_connection')
async def test_listen_to_bus_connection_refused(mock_open_connection, caplog):
    """Test listen_to_bus handles ConnectionRefusedError."""
    mock_open_connection.side_effect = ConnectionRefusedError

    with caplog.at_level(logging.ERROR):
        await listen_to_bus()

        mock_open_connection.assert_called_once_with(EVENT_BUS_HOST, EVENT_BUS_PORT)
        assert "Connection refused. Is the event bus server running?" in caplog.text


@pytest.mark.asyncio
@patch('asyncio.open_connection')
async def test_listen_to_bus_generic_connection_error(mock_open_connection, caplog):
    """Test listen_to_bus handles generic Exception during connection."""
    mock_open_connection.side_effect = Exception("Failed to connect")

    with caplog.at_level(logging.ERROR):
        await listen_to_bus()

        mock_open_connection.assert_called_once_with(EVENT_BUS_HOST, EVENT_BUS_PORT)
        assert "Error connecting to event bus: Failed to connect" in caplog.text


@pytest.mark.asyncio
async def test_listen_to_bus_exception_during_listening(caplog):
    """Test listen_to_bus handles Exception during message listening."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_writer = AsyncMock(spec=asyncio.StreamWriter)
    # Mock is_closing to return False so that close() is called
    mock_writer.is_closing.return_value = False

    # Patch open_connection inside the test to control its return values
    with patch('asyncio.open_connection', return_value=(mock_reader, mock_writer)) as mock_open_connection:
        mock_reader.readline.side_effect = [
            b"initial message\n",
            Exception("Error during read") # Simulate error after first message
        ]

        # Change caplog level to INFO to capture both INFO and ERROR messages
        with caplog.at_level(logging.INFO): 
            await listen_to_bus()

            mock_open_connection.assert_called_once()
            mock_reader.readline.assert_has_calls([call(), call()])
            assert "Received from bus: initial message" in caplog.text
            assert "An error occurred: Error during read" in caplog.text
            
            mock_writer.close.assert_called_once()
            mock_writer.wait_closed.assert_called_once()