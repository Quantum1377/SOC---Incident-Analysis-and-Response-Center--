import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call
from event_client import EventClient
import logging



@pytest.fixture
def event_client_instance():
    """Provides a fresh EventClient instance for each test."""
    return EventClient("TestClient", host='127.0.0.1', port=9999)

@pytest.mark.asyncio
async def test_event_client_init(event_client_instance):
    """Test EventClient initialization."""
    assert event_client_instance.name == "TestClient"
    assert event_client_instance._host == '127.0.0.1'
    assert event_client_instance._port == 9999
    assert event_client_instance._writer is None

@pytest.mark.asyncio
@patch('asyncio.open_connection')
async def test_connect_success(mock_open_connection, event_client_instance):
    """Test successful client connection."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_writer = AsyncMock(spec=asyncio.StreamWriter)
    mock_open_connection.return_value = (mock_reader, mock_writer)

    reader, writer = await event_client_instance.connect()

    mock_open_connection.assert_called_once_with('127.0.0.1', 9999)
    assert event_client_instance._writer is mock_writer
    assert reader is mock_reader
    assert writer is mock_writer

@pytest.mark.asyncio
@patch('asyncio.open_connection')
async def test_connect_connection_refused(mock_open_connection, event_client_instance, caplog):
    """Test client connection with ConnectionRefusedError."""
    mock_open_connection.side_effect = ConnectionRefusedError

    with caplog.at_level(logging.ERROR):
        reader, writer = await event_client_instance.connect()

        mock_open_connection.assert_called_once_with('127.0.0.1', 9999)
        assert event_client_instance._writer is None
        assert reader is None
        assert writer is None
        assert "Connection refused" in caplog.text

@pytest.mark.asyncio
@patch('asyncio.open_connection')
async def test_connect_generic_exception(mock_open_connection, event_client_instance, caplog):
    """Test client connection with a generic Exception."""
    mock_open_connection.side_effect = Exception("Test error")

    with caplog.at_level(logging.ERROR):
        reader, writer = await event_client_instance.connect()

        mock_open_connection.assert_called_once_with('127.0.0.1', 9999)
        assert event_client_instance._writer is None
        assert reader is None
        assert writer is None
        assert "Error connecting client TestClient: Test error" in caplog.text

@pytest.mark.asyncio
async def test_send_message_when_connected(event_client_instance):
    """Test sending a message when the client is connected."""
    mock_writer = AsyncMock(spec=asyncio.StreamWriter)
    event_client_instance._writer = mock_writer

    message_content = "Hello EventBus!"
    expected_full_message = "[TestClient] Hello EventBus!\n"
    
    await event_client_instance.send_message(message_content)

    mock_writer.write.assert_called_once_with(expected_full_message.encode())
    mock_writer.drain.assert_called_once()

@pytest.mark.asyncio
async def test_send_message_when_not_connected(event_client_instance, caplog):
    """Test sending a message when the client is not connected."""
    event_client_instance._writer = None # Ensure not connected

    message_content = "Hello EventBus!"
    
    with caplog.at_level(logging.WARNING):
        await event_client_instance.send_message(message_content)

        assert "Client TestClient not connected. Cannot send message." in caplog.text
        # Ensure no attempts to write or drain
        assert not event_client_instance._writer # Still None
        # if there was a mock, we would assert_not_called()

@pytest.mark.asyncio
async def test_listen_for_messages_receives_and_logs(event_client_instance, caplog):
    """Test listening for messages and logging them."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_reader.readline.side_effect = [
        b"[EventBus] Message 1\n",
        b"[EventBus] Message 2\n",
        b"" # EOF to stop the loop
    ]

    with caplog.at_level(logging.INFO):
        # We need to run listen_for_messages in a separate task as it's an infinite loop
        listen_task = asyncio.create_task(event_client_instance.listen_for_messages(mock_reader))
        await asyncio.sleep(0.01) # Give task a chance to run
        listen_task.cancel() # Cancel the task after messages are processed
        try:
            await listen_task
        except asyncio.CancelledError:
            pass # Expected

        mock_reader.readline.assert_has_calls([call(), call(), call()])
        assert "Received: [EventBus] Message 1" in caplog.text
        assert "Received: [EventBus] Message 2" in caplog.text
        assert "Event bus disconnected from client TestClient." in caplog.text

@pytest.mark.asyncio
async def test_listen_for_messages_on_connection_reset_error(event_client_instance, caplog):
    """Test listen for messages handles ConnectionResetError."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_reader.readline.side_effect = ConnectionResetError("Connection reset by peer")

    with caplog.at_level(logging.WARNING):
        listen_task = asyncio.create_task(event_client_instance.listen_for_messages(mock_reader))
        await asyncio.sleep(0.01)
        listen_task.cancel()
        try:
            await listen_task
        except asyncio.CancelledError:
            pass

        mock_reader.readline.assert_called_once() # Only called once before error
        assert "Event bus reset connection with client TestClient." in caplog.text

@pytest.mark.asyncio
async def test_listen_for_messages_on_generic_exception(event_client_instance, caplog):
    """Test listen for messages handles a generic Exception."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_reader.readline.side_effect = Exception("Parsing error")

    with caplog.at_level(logging.ERROR):
        listen_task = asyncio.create_task(event_client_instance.listen_for_messages(mock_reader))
        await asyncio.sleep(0.01)
        listen_task.cancel()
        try:
            await listen_task
        except asyncio.CancelledError:
            pass

        mock_reader.readline.assert_called_once()
        assert "Error listening for messages for client TestClient: Parsing error" in caplog.text

@pytest.mark.asyncio
async def test_close_when_connected(event_client_instance):
    """Test closing connection when client is connected."""
    mock_writer = AsyncMock(spec=asyncio.StreamWriter)
    event_client_instance._writer = mock_writer

    await event_client_instance.close()

    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_called_once()
    # _writer should not be None after close, as it's not set to None inside close() method

@pytest.mark.asyncio
async def test_close_when_not_connected(event_client_instance, caplog):
    """Test closing connection when client is not connected."""
    event_client_instance._writer = None # Ensure not connected

    with caplog.at_level(logging.INFO): # No warning/error expected, just info if it tried to close
        await event_client_instance.close()
        # No error should occur, and no logging about closing an already closed connection
        assert not caplog.records