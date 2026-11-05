using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Likvido.Http.Tests.Support;

internal sealed record LogEntry(string Category, LogLevel Level, string Message);

/// <summary>Captures every log line written through the service provider, from every category.</summary>
internal sealed class CapturedLogs : ILoggerProvider
{
    private readonly ConcurrentQueue<LogEntry> _entries = new();

    internal IReadOnlyCollection<LogEntry> Entries => _entries;

    internal IReadOnlyList<LogEntry> Guard =>
        _entries.Where(entry => entry.Category == "Likvido.Http.OutboundRequestGuard").ToList();

    public ILogger CreateLogger(string categoryName) => new Logger(categoryName, _entries);

    public void Dispose()
    {
    }

    private sealed class Logger(string category, ConcurrentQueue<LogEntry> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            entries.Enqueue(new LogEntry(category, logLevel, formatter(state, exception)));
    }
}
