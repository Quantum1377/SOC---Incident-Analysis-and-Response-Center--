import pytest
import asyncio
from unittest.mock import AsyncMock, patch, mock_open, call
import logging
import json
import io
from log_producer import tail_log_and_publish, EVENT_BUS_HOST, EVENT_BUS_PORT, LOG_FILE_TO_WATCH, CLIENT_NAME

# Helper to simulate an asyncio.StreamWriter that we can inspect
class MockStreamWriter:
    def __init__(self):
        self.writes = []
        self._closing = False

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        pass # Simulate drainage

    def close(self):
        self._closing = True

    async def wait_closed(self):
        self._closing = True

    def is_closing(self):
        return self._closing

@pytest.fixture(autouse=True)
def no_sleeps(monkeypatch):
    """Speeds up tests by preventing asyncio.sleep."""
    async def no_op_sleep(delay):
        pass
    monkeypatch.setattr(asyncio, "sleep", no_op_sleep)

@pytest.வதால்(autouse=True)
async def connection_called_event():
    """An asyncio.Event to signal when open_connection is called."""
    return asyncio.Event()

@pytest.fixture(autouse=True)
async def file_opened_event():
    """An asyncio.Event to signal when builtins.open is called."""
    return asyncio.Event()


@pytest.mark.asyncio
@patch('asyncio.open_connection')
@patch('builtins.open', new_callable=mock_open)
async def test_tail_and_publish_success(
    mock_builtins_open, mock_open_connection, caplog, connection_called_event, file_opened_event
):
    """Test successful log tailing and publishing."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_writer = MockStreamWriter() # Use our custom mock writer

    async def _mock_open_connection_side_effect(*args, **kwargs):
        connection_called_event.set() # Signal that open_connection was called
        return mock_reader, mock_writer
    mock_open_connection.side_effect = _mock_open_connection_side_effect

    mock_file_handle = mock_builtins_open.return_value
    def _mock_open_side_effect(*args, **kwargs):
        file_opened_event.set() # Signal that builtins.open was called
        return mock_file_handle
    mock_builtins_open.side_effect = _mock_open_side_effect

    mock_file_handle.seek.return_value = 0 # Start at beginning
    mock_file_handle.readline.side_effect = [
        "log line 1\n",
        "log line 2\n",
        "", # Simulate no new lines for a while
        "log line 3\n",
        "" # Stop after this to exit the while loop
    ]

    with caplog.at_level(logging.INFO):
        tail_task = asyncio.create_task(tail_log_and_publish())
        
        # Await the events to ensure these calls have happened
        await asyncio.wait_for(connection_called_event.wait(), timeout=1)
        await asyncio.wait_for(file_opened_event.wait(), timeout=1)
        
        mock_open_connection.assert_called_once_with(EVENT_BUS_HOST, EVENT_BUS_PORT)
        mock_builtins_open.assert_called_once_with(LOG_FILE_TO_WATCH, 'r')
        mock_file_handle.seek.assert_called_once_with(0, 2) # Initial seek to end

        # Give it time to process the lines and ensure broadcast happens
        await asyncio.sleep(0.01) # A small sleep to let the task execute its loop
        tail_task.cancel()
        try:
            await tail_task
        except asyncio.CancelledError:
            pass
        
        assert "Connected to event bus" in caplog.text
        assert "Tailing log file" in caplog.text
        assert "New log entry found: log line 1" in caplog.text
        assert "New log entry found: log line 2" in caplog.text
        assert "Published log entry to event bus."
        assert "New log entry found: log line 3" in caplog.text

        # Verify messages sent
        assert len(mock_writer.writes) == 3
        expected_event1 = json.dumps({"source": CLIENT_NAME, "type": "LOG_ENTRY", "payload": "log line 1"}) + "\n"
        expected_event2 = json.dumps({"source": CLIENT_NAME, "type": "LOG_ENTRY", "payload": "log line 2"}) + "\n"
        expected_event3 = json.dumps({"source": CLIENT_NAME, "type": "LOG_ENTRY", "payload": "log line 3"}) + "\n"
        assert mock_writer.writes[0].decode() == expected_event1
        assert mock_writer.writes[1].decode() == expected_event2
        assert mock_writer.writes[2].decode() == expected_event3
        
        assert mock_writer.is_closing() # Should be closing

@pytest.mark.asyncio
@patch('asyncio.open_connection')
async def test_tail_and_publish_connection_refused(mock_open_connection, caplog):
    """Test log producer handles ConnectionRefusedError."""
    mock_open_connection.side_effect = ConnectionRefusedError

    with caplog.at_level(logging.ERROR):
        await tail_log_and_publish()

        mock_open_connection.assert_called_once_with(EVENT_BUS_HOST, EVENT_BUS_PORT)
        assert "Connection refused. Is the event bus server running?" in caplog.text

@pytest.mark.asyncio
@patch('builtins.open', new_callable=mock_open)
async def test_tail_and_publish_file_not_found(
    mock_builtins_open, caplog # Need file_opened_event here too
):
    """Test log producer handles FileNotFoundError."""
    def _mock_open_side_effect(*args, **kwargs):
        file_opened_event.set() # Signal that builtins.open was called
        raise FileNotFoundError
    mock_builtins_open.side_effect = _mock_open_side_effect

    with caplog.at_level(logging.ERROR):
        tail_task = asyncio.create_task(tail_log_and_publish())
        await asyncio.wait_for(file_opened_event.wait(), timeout=1) # Await file open event

        # Ensure task is cancelled after error
        tail_task.cancel()
        try:
            await tail_task
        except asyncio.CancelledError:
            pass

        mock_builtins_open.assert_called_once_with(LOG_FILE_TO_WATCH, 'r')
        assert f"Log file not found: {LOG_FILE_TO_WATCH}. Please create it." in caplog.text

@pytest.mark.asyncio
@patch('asyncio.open_connection')
@patch('builtins.open', new_callable=mock_open)
async def test_tail_and_publish_exception_during_tailing(
    mock_builtins_open, mock_open_connection, caplog, connection_called_event, file_opened_event
):
    """Test log producer handles generic Exception during file tailing."""
    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_writer = MockStreamWriter()

    async def _mock_open_connection_side_effect(*args, **kwargs):
        connection_called_event.set()
        return mock_reader, mock_writer
    mock_open_connection.side_effect = _mock_open_connection_side_effect

    def _mock_open_side_effect(*args, **kwargs):
        file_opened_event.set()
        return mock_file_handle
    mock_builtins_open.side_effect = _mock_open_side_effect


    mock_file_handle = mock_builtins_open.return_value
    mock_file_handle.seek.return_value = 0
    mock_file_handle.readline.side_effect = [
        "valid log line\n",
        Exception("Error during readline") # Simulate error
    ]

    with caplog.at_level(logging.ERROR):
        tail_task = asyncio.create_task(tail_log_and_publish())
        await asyncio.wait_for(connection_called_event.wait(), timeout=1)
        await asyncio.wait_for(file_opened_event.wait(), timeout=1)

        await asyncio.sleep(0.01) # Give it time to process
        tail_task.cancel() # Cancel to stop the infinite loop
        try:
            await tail_task
        except asyncio.CancelledError:
            pass

        mock_open_connection.assert_called_once()
        mock_builtins_open.assert_called_once()
        
        assert "New log entry found: valid log line" in caplog.text
        assert "An error occurred: Error during readline" in caplog.text
        
        assert mock_writer.is_closing() # Should be closing
        assert len(mock_writer.writes) == 1 # Only the first log line should be sent