using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace AvmController
{
    public partial class MainWindow : Window
    {
        private readonly ObservableCollection<TelemetryItem> _telemetry = new ObservableCollection<TelemetryItem>();
        private readonly List<AvmTargetEntry> _targets = new List<AvmTargetEntry>();
        private readonly List<AvmFileRule> _fileRules = new List<AvmFileRule>();
        private readonly DispatcherTimer _timer;

        public MainWindow()
        {
            InitializeComponent();
            DataContext = this;
            Telemetry = _telemetry;

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) };
            _timer.Tick += (_, __) => RefreshState();
            _timer.Start();
        }

        public ObservableCollection<TelemetryItem> Telemetry { get; }

        private void RefreshButton_Click(object sender, RoutedEventArgs e) => RefreshState();

        private void AddTargetButton_Click(object sender, RoutedEventArgs e)
        {
            var kind = (AvmTargetKind)TargetKindCombo.SelectedIndex;
            var value = TargetValueText.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            var target = new AvmTargetEntry
            {
                Kind = (uint)kind,
                Pattern = value,
                ProcessId = kind == AvmTargetKind.Pid && uint.TryParse(value, out var pid) ? pid : 0
            };

            _targets.Add(target);
            TargetsList.Items.Add($"{kind}: {value}");
            TargetValueText.Clear();
        }

        private void InjectShimButton_Click(object sender, RoutedEventArgs e)
        {
            if (!uint.TryParse(TargetValueText.Text, out var processId))
            {
                MessageBox.Show("Enter a numeric PID in the target field.", "Inject Shim", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                InjectionService.InjectShim(processId);
                TargetsList.Items.Add($"Shim injected → PID {processId}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Injection failed: {ex.Message}", "Inject Shim", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LaunchWithShimButton_Click(object sender, RoutedEventArgs e)
        {
            var path = LaunchPathText.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(path))
            {
                var dialog = new Microsoft.Win32.OpenFileDialog
                {
                    Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
                    Title  = "Select executable to launch with shim"
                };
                if (dialog.ShowDialog(this) != true) return;
                path = dialog.FileName;
                LaunchPathText.Text = path;
            }

            try
            {
                var pid = InjectionService.LaunchWithShim(path);
                TargetsList.Items.Add($"Launched with shim → PID {pid}  [{System.IO.Path.GetFileName(path)}]");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Launch failed: {ex.Message}", "Launch with Shim", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void AddHideRuleButton_Click(object sender, RoutedEventArgs e)
        {
            var match = MatchPathText.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(match))
            {
                return;
            }

            _fileRules.Add(new AvmFileRule
            {
                Action = 1,
                MatchPath = match,
                RedirectPath = string.Empty
            });

            RulesList.Items.Add($"Hide: {match}");
        }

        private void AddRedirectRuleButton_Click(object sender, RoutedEventArgs e)
        {
            var match = MatchPathText.Text?.Trim() ?? string.Empty;
            var redirect = RedirectPathText.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(match) || string.IsNullOrWhiteSpace(redirect))
            {
                return;
            }

            _fileRules.Add(new AvmFileRule
            {
                Action = 2,
                MatchPath = match,
                RedirectPath = redirect
            });

            RulesList.Items.Add($"Redirect: {match} -> {redirect}");
        }

        private void RemoveRuleButton_Click(object sender, RoutedEventArgs e)
        {
            var index = RulesList.SelectedIndex;
            if (index < 0 || index >= _fileRules.Count)
            {
                return;
            }

            _fileRules.RemoveAt(index);
            RulesList.Items.RemoveAt(index);
        }

        private void ClearRulesButton_Click(object sender, RoutedEventArgs e)
        {
            _fileRules.Clear();
            RulesList.Items.Clear();
        }

        private void ApplyPolicyButton_Click(object sender, RoutedEventArgs e)
        {
            var policy = BuildPolicy();
            using (var kernel = new KernelClient())
            {
                if (kernel.IsConnected)
                {
                    kernel.SetPolicy(policy);
                    kernel.ClearTargets();
                    kernel.ClearFileRules();
                    foreach (var target in _targets)
                    {
                        kernel.AddTarget(target);
                    }
                    foreach (var rule in _fileRules)
                    {
                        kernel.AddFileRule(rule);
                    }
                }
            }

            using (var filter = new MiniFilterClient())
            {
                if (filter.IsConnected)
                {
                    filter.SetPolicy(policy, _targets, _fileRules);
                }
            }

            RefreshState();
        }

        private void ExportLogsButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "JSON (*.json)|*.json|CSV (*.csv)|*.csv",
                AddExtension = true
            };

            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            if (dialog.FileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                File.WriteAllText(dialog.FileName, BuildJsonExport());
                return;
            }

            var builder = new StringBuilder();
            builder.AppendLine("Timestamp,Source,Type,PID,TID,Mechanism,Original,Spoofed,Image");
            foreach (var item in _telemetry)
            {
                builder.AppendLine($"\"{item.Timestamp:o}\",\"{item.Source}\",\"{item.EventType}\",{item.ProcessId},{item.ThreadId},\"{item.Mechanism}\",\"{item.OriginalText}\",\"{item.SpoofedText}\",\"{item.ImagePath}\"");
            }
            File.WriteAllText(dialog.FileName, builder.ToString());
        }

        private AvmPolicy BuildPolicy()
        {
            AvmCheckFlags flags = 0;

            if (DebuggerCheck.IsChecked == true) flags |= AvmCheckFlags.Debugger;
            if (TimingCheck.IsChecked == true) flags |= AvmCheckFlags.Timing;
            if (NativeApiCheck.IsChecked == true) flags |= AvmCheckFlags.NativeApi;
            if (ProcessEnumCheck.IsChecked == true) flags |= AvmCheckFlags.ProcessEnum;
            if (DriverProbeCheck.IsChecked == true) flags |= AvmCheckFlags.DriverDeviceProbe;
            if (RegistryCheck.IsChecked == true) flags |= AvmCheckFlags.RegistryArtifacts;
            if (FileCheck.IsChecked == true) flags |= AvmCheckFlags.FileArtifacts;
            if (DirectoryCheck.IsChecked == true) flags |= AvmCheckFlags.DirectoryFilter;

            return new AvmPolicy
            {
                Version = 1,
                Mode = (uint)ModeCombo.SelectedIndex,
                EnabledChecks = (uint)flags,
                EventQueueCapacity = 512,
                RuntimePolicyRefreshMs = 1000,
                DefaultConcealmentMask = (uint)flags,
                DefaultLogMask = 0xFFFFFFFF
            };
        }

        private void RefreshState()
        {
            using (var kernel = new KernelClient())
            {
                KernelStatusText.Text = kernel.IsConnected ? "Kernel: connected" : "Kernel: disconnected";
                if (kernel.IsConnected)
                {
                    var status = kernel.GetStatus();
                    KernelMetricsText.Text = string.Format("Targets: {0}  Events: {1}  Checks: 0x{2:X8}", status.TargetCount, status.EventCount, status.EnabledChecks);
                    AppendEvents(kernel.FetchEvents(), "Kernel");
                }
            }

            using (var filter = new MiniFilterClient())
            {
                FilterStatusText.Text = filter.IsConnected ? "Minifilter: connected" : "Minifilter: disconnected";
                if (filter.IsConnected)
                {
                    var status = filter.GetStatus();
                    FilterMetricsText.Text = string.Format("Rules: {0}  Events: {1}", status.FileRuleCount, status.EventCount);
                    AppendEvents(filter.FetchEvents(), "MiniFilter");
                }
            }
        }

        private string BuildJsonExport()
        {
            var builder = new StringBuilder();
            builder.AppendLine("[");

            for (var index = 0; index < _telemetry.Count; index++)
            {
                var item = _telemetry[index];
                builder.Append("  {");
                builder.AppendFormat("\"timestamp\":\"{0:o}\",", item.Timestamp);
                builder.AppendFormat("\"source\":\"{0}\",", EscapeJson(item.Source));
                builder.AppendFormat("\"eventType\":\"{0}\",", EscapeJson(item.EventType));
                builder.AppendFormat("\"processId\":{0},", item.ProcessId);
                builder.AppendFormat("\"threadId\":{0},", item.ThreadId);
                builder.AppendFormat("\"imagePath\":\"{0}\",", EscapeJson(item.ImagePath));
                builder.AppendFormat("\"mechanism\":\"{0}\",", EscapeJson(item.Mechanism));
                builder.AppendFormat("\"originalText\":\"{0}\",", EscapeJson(item.OriginalText));
                builder.AppendFormat("\"spoofedText\":\"{0}\",", EscapeJson(item.SpoofedText));
                builder.AppendFormat("\"originalStatus\":{0},", item.OriginalStatus);
                builder.AppendFormat("\"spoofedStatus\":{0}", item.SpoofedStatus);
                builder.Append("}");
                builder.AppendLine(index == _telemetry.Count - 1 ? string.Empty : ",");
            }

            builder.AppendLine("]");
            return builder.ToString();
        }

        private static string EscapeJson(string value)
        {
            return (value ?? string.Empty).Replace("\\", "\\\\").Replace("\"", "\\\"");
        }

        private void AppendEvents(IReadOnlyList<AvmEventRecord> events, string defaultSource)
        {
            foreach (var record in events)
            {
                _telemetry.Insert(0, new TelemetryItem
                {
                    Timestamp = DateTime.FromFileTimeUtc(record.Timestamp).ToLocalTime(),
                    Source = string.IsNullOrWhiteSpace(defaultSource) ? record.Source.ToString() : defaultSource,
                    EventType = record.Kind.ToString(),
                    ProcessId = record.ProcessId,
                    ThreadId = record.ThreadId,
                    ImagePath = record.ImagePath,
                    Mechanism = record.Mechanism,
                    OriginalText = record.OriginalText,
                    SpoofedText = record.SpoofedText,
                    OriginalStatus = record.OriginalStatus,
                    SpoofedStatus = record.SpoofedStatus
                });
            }

            while (_telemetry.Count > 500)
            {
                _telemetry.RemoveAt(_telemetry.Count - 1);
            }
        }
    }
}
