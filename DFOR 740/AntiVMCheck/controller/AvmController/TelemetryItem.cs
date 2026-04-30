using System;

namespace AvmController
{
    public sealed class TelemetryItem
    {
        public DateTime Timestamp { get; set; }
        public string Source { get; set; }
        public string QueryCategory { get; set; }
        public string EventType { get; set; }
        public uint ProcessId { get; set; }
        public uint ThreadId { get; set; }
        public string ImagePath { get; set; }
        public string Mechanism { get; set; }
        public string OriginalText { get; set; }
        public string SpoofedText { get; set; }
        public int OriginalStatus { get; set; }
        public int SpoofedStatus { get; set; }
    }
}
