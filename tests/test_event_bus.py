import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call
from event_bus import EventBus
import logging

logging.getLogger('EventBus').setLevel(logging.CRITICAL)

@pytest.fixture
def event_bus_instance():
    """Provides a fresh EventBus instance for each test."""
    return EventBus(host='127.0.0.1', port=9999, use_ssl=False)

@pytest.fixture
def mock_stream_writer():
    """Provides a mock asyncio.StreamWriter."""
    writer = AsyncMock(spec=asyncio.StreamWriter)
    writer.get_extra_info.return_value = ('127.0.0.1', 12345)
    return writer

@pytest.mark.asyncio
async def test_event_bus_init(event_bus_instance):
    """Test EventBus initialization."""
    assert event_bus_instance._host == '127.0.0.1'
    assert event_bus_instance._port == 9999
    assert event_bus_instance._writers == []

@pytest.mark.asyncio
async def test_broadcast_sends_to_all_writers(event_bus_instance):
    """Test that _broadcast sends message to all connected writers."""
    mock_writer1 = AsyncMock(spec=asyncio.StreamWriter)
    mock_writer2 = AsyncMock(spec=asyncio.StreamWriter)

    event_bus_instance._writers.append(mock_writer1)
    event_bus_instance._writers.append(mock_writer2)

    message = "test message\n"
    await event_bus_instance._broadcast(message)

    mock_writer1.write.assert_called_once_with(message.encode())
    mock_writer1.drain.assert_called_once()
    mock_writer2.write.assert_called_once_with(message.encode())
    mock_writer2.drain.assert_called_once()

@pytest.mark.asyncio
async def test_broadcast_removes_disconnected_writer_on_connection_error(event_bus_instance):
    """Test that _broadcast removes a writer if ConnectionError occurs."""
    mock_writer1 = AsyncMock(spec=asyncio.StreamWriter)
    mock_writer2 = AsyncMock(spec=asyncio.StreamWriter)

    mock_writer1.write.side_effect = ConnectionError("Client disconnected")

    event_bus_instance._writers.append(mock_writer1)
    event_bus_instance._writers.append(mock_writer2)

    message = "test message\n"
    await event_bus_instance._broadcast(message)

    assert mock_writer1 not in event_bus_instance._writers
    assert mock_writer2 in event_bus_instance._writers
    
    mock_writer1.close.assert_called_once()
    mock_writer1.wait_closed.assert_called_once()
    mock_writer2.write.assert_called_once_with(message.encode())
    mock_writer2.drain.assert_called_once()

@pytest.mark.asyncio
@patch('event_bus.EventBus._broadcast', new_callable=AsyncMock)
async def test_handle_client_receives_and_broadcasts_message_then_disconnects(
    mock_broadcast, event_bus_instance, mock_stream_writer
):
    """Test handle_client receives a message, broadcasts it, and handles clean disconnect."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    # Simulate receiving a message, then an EOF (clean disconnect)
    mock_reader.readline.side_effect = [b"hello world\n", b""]

    # Ensure the writer is added to _writers when handle_client is called
    assert mock_stream_writer not in event_bus_instance._writers

    # Run handle_client
    await event_bus_instance.handle_client(mock_reader, mock_stream_writer)

    # Assertions
    mock_reader.readline.assert_has_calls([
        call(), # First call for "hello world\n"
        call()  # Second call for "" (EOF)
    ])
    mock_broadcast.assert_called_once_with("hello world\n")
    assert mock_stream_writer not in event_bus_instance._writers  # Should be removed on disconnect
    mock_stream_writer.close.assert_called_once()
    mock_stream_writer.wait_closed.assert_called_once()

@pytest.mark.asyncio
@patch('event_bus.EventBus._broadcast', new_callable=AsyncMock)
async def test_handle_client_removes_writer_on_connection_reset_error(
    mock_broadcast, event_bus_instance, mock_stream_writer
):
    """Test handle_client removes writer on ConnectionResetError."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_reader.readline.side_effect = ConnectionResetError("Client forcibly closed")

    assert mock_stream_writer not in event_bus_instance._writers

    await event_bus_instance.handle_client(mock_reader, mock_stream_writer)

    mock_reader.readline.assert_called_once()
    mock_broadcast.assert_not_called()  # No message to broadcast
    assert mock_stream_writer not in event_bus_instance._writers
    mock_stream_writer.close.assert_called_once()
    mock_stream_writer.wait_closed.assert_called_once()