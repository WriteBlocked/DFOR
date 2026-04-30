using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Threading;

namespace AvmController
{
    public partial class MainWindow : Window
    {
        private readonly ObservableCollection<TelemetryItem> _telemetry = new ObservableCollection<TelemetryItem>();
        private readonly List<AvmTargetEntry> _targets = new List<AvmTargetEntry>();
        private readonly List<AvmFileRule> _fileRules = new List<AvmFileRule>();
        private readonly DispatcherTimer _timer;
        private readonly ICollectionView _telemetryView;

        public MainWindow()
        {
            InitializeComponent();
            DataContext = this;
            Telemetry = _telemetry;
            _telemetryView = CollectionViewSource.GetDefaultView(_telemetry);
            _telemetryView.Filter = FilterTelemetryItem;
            Loaded += MainWindow_Loaded;

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) };
            _timer.Tick += (_, __) => RefreshState();
            _timer.Start();
            ApplyTelemetrySort(false);
        }

        public ObservableCollection<TelemetryItem> Telemetry { get; }

        private void RefreshButton_Click(object sender, RoutedEventArgs e) => RefreshState();

        private void TelemetryFilterText_TextChanged(object sender, TextChangedEventArgs e)
        {
            _telemetryView.Refresh();
        }

        private void SortTelemetryNewest_Click(object sender, RoutedEventArgs e)
        {
            ApplyTelemetrySort(false);
        }

        private void SortTelemetryOldest_Click(object sender, RoutedEventArgs e)
        {
            ApplyTelemetrySort(true);
        }

        private void ClearTelemetryButton_Click(object sender, RoutedEventArgs e)
        {
            _telemetry.Clear();
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            RefreshState();
            TryAutoApplyDefaultPolicy();
        }

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
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Launch with Shim — select executable",
                Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*"
            };

            if (dialog.ShowDialog(this) != true) return;

            var exePath  = dialog.FileName;
            var fileName = System.IO.Path.GetFileName(exePath);
            var outputTextBox = CreateOutputWindow(fileName);
            AppendOutput(outputTextBox, $"Launching {fileName} with shim...{Environment.NewLine}");

            TargetsList.Items.Add($"Launching {fileName} with shim…");

            System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    var output = InjectionService.LaunchWithShimCaptured(
                        exePath,
                        out var pid,
                        onOutputChunk: chunk => Dispatcher.Invoke(() => AppendOutput(outputTextBox, chunk)),
                        onStatus: status => Dispatcher.Invoke(() => AppendStatus(outputTextBox, status)),
                        onStarted: startedPid => Dispatcher.Invoke(() =>
                        {
                            TargetsList.Items.Add($"Shim launched → PID {startedPid}");
                            AppendOutput(outputTextBox, $"PID {startedPid} started.{Environment.NewLine}");
                        }));

                    Dispatcher.Invoke(() =>
                    {
                        TargetsList.Items.Add($"Shim run complete → PID was {pid}");
                        if (!string.IsNullOrWhiteSpace(outputTextBox.Text)
                            && !string.Equals(outputTextBox.Text.Trim(), output.Trim(), StringComparison.Ordinal))
                        {
                            AppendOutput(outputTextBox, Environment.NewLine);
                            AppendOutput(outputTextBox, output);
                        }
                        else if (string.IsNullOrWhiteSpace(outputTextBox.Text))
                        {
                            AppendOutput(outputTextBox, output);
                        }
                    });
                }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() =>
                    {
                        AppendOutput(outputTextBox, $"{Environment.NewLine}Launch failed: {ex.Message}{Environment.NewLine}");
                        MessageBox.Show($"Launch failed: {ex.Message}", "Launch with Shim",
                                        MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            });
        }

        private TextBox CreateOutputWindow(string title)
        {
            var tb = new System.Windows.Controls.TextBox
            {
                Text                          = string.Empty,
                IsReadOnly                    = true,
                FontFamily                    = new System.Windows.Media.FontFamily("Consolas"),
                FontSize                      = 12,
                Foreground                    = System.Windows.Media.Brushes.Black,
                Background                    = System.Windows.Media.Brushes.White,
                VerticalScrollBarVisibility   = System.Windows.Controls.ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = System.Windows.Controls.ScrollBarVisibility.Auto,
                TextWrapping                  = System.Windows.TextWrapping.NoWrap
            };
            new Window
            {
                Title   = $"Output — {title}",
                Width   = 920,
                Height  = 640,
                Owner   = this,
                Content = tb,
                Background = System.Windows.Media.Brushes.White
            }.Show();
            return tb;
        }

        private static void AppendOutput(TextBox tb, string content)
        {
            if (tb == null || string.IsNullOrEmpty(content))
            {
                return;
            }

            tb.AppendText(content);
            tb.CaretIndex = tb.Text.Length;
            tb.ScrollToEnd();
        }

        private static void AppendStatus(TextBox tb, string status)
        {
            if (tb == null || string.IsNullOrWhiteSpace(status))
            {
                return;
            }

            if (tb.Text.Length > 0 && !tb.Text.EndsWith(Environment.NewLine, StringComparison.Ordinal))
            {
                tb.AppendText(Environment.NewLine);
            }

            tb.AppendText(status + Environment.NewLine);
            tb.CaretIndex = tb.Text.Length;
            tb.ScrollToEnd();
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

        private void TryAutoApplyDefaultPolicy()
        {
            try
            {
                var policy = BuildPolicy();
                var applied = false;

                using (var kernel = new KernelClient())
                {
                    if (kernel.IsConnected)
                    {
                        kernel.SetPolicy(policy);
                        kernel.ClearTargets();
                        kernel.ClearFileRules();
                        applied = true;
                    }
                }

                using (var filter = new MiniFilterClient())
                {
                    if (filter.IsConnected)
                    {
                        filter.SetPolicy(policy, Array.Empty<AvmTargetEntry>(), Array.Empty<AvmFileRule>());
                        applied = true;
                    }
                }

                if (applied)
                {
                    TargetsList.Items.Add("Default full-concealment policy applied on startup");
                    RefreshState();
                }
            }
            catch (Exception ex)
            {
                TargetsList.Items.Add($"Auto-apply skipped: {ex.Message}");
            }
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
            builder.AppendLine("Timestamp,Source,Category,Type,PID,TID,Mechanism,Original,Spoofed,Image");
            foreach (var item in _telemetry)
            {
                builder.AppendLine($"\"{item.Timestamp:o}\",\"{item.Source}\",\"{item.QueryCategory}\",\"{item.EventType}\",{item.ProcessId},{item.ThreadId},\"{item.Mechanism}\",\"{item.OriginalText}\",\"{item.SpoofedText}\",\"{item.ImagePath}\"");
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
                builder.AppendFormat("\"category\":\"{0}\",", EscapeJson(item.QueryCategory));
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

        private static string TryGetProcessName(uint pid)
        {
            try
            {
                var p = Process.GetProcessById((int)pid);
                return p.ProcessName;
            }
            catch
            {
                return null;
            }
        }

        private void AppendEvents(IReadOnlyList<AvmEventRecord> events, string defaultSource)
        {
            foreach (var record in events)
            {
                var imagePath = record.ImagePath;
                if (string.IsNullOrWhiteSpace(imagePath) && record.ProcessId > 0)
                {
                    imagePath = TryGetProcessName(record.ProcessId) ?? $"PID {record.ProcessId}";
                }

                _telemetry.Insert(0, new TelemetryItem
                {
                    Timestamp = DateTime.FromFileTimeUtc(record.Timestamp).ToLocalTime(),
                    Source = string.IsNullOrWhiteSpace(defaultSource) ? record.Source.ToString() : defaultSource,
                    QueryCategory = ClassifyTelemetry(record),
                    EventType = record.Kind.ToString(),
                    ProcessId = record.ProcessId,
                    ThreadId = record.ThreadId,
                    ImagePath = imagePath,
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

            _telemetryView.Refresh();
        }

        private bool FilterTelemetryItem(object obj)
        {
            if (!(obj is TelemetryItem item))
            {
                return false;
            }

            var filter = TelemetryFilterText?.Text?.Trim();
            if (string.IsNullOrWhiteSpace(filter))
            {
                return true;
            }

            filter = filter.ToLowerInvariant();
            return ContainsFilter(item.Source, filter)
                || ContainsFilter(item.QueryCategory, filter)
                || ContainsFilter(item.ImagePath, filter)
                || ContainsFilter(item.OriginalText, filter)
                || ContainsFilter(item.SpoofedText, filter)
                || item.ProcessId.ToString().Contains(filter);
        }

        private static bool ContainsFilter(string value, string filter)
        {
            return !string.IsNullOrWhiteSpace(value)
                && value.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private void ApplyTelemetrySort(bool oldestFirst)
        {
            _telemetryView.SortDescriptions.Clear();
            _telemetryView.SortDescriptions.Add(
                new SortDescription(nameof(TelemetryItem.Timestamp),
                    oldestFirst ? ListSortDirection.Ascending : ListSortDirection.Descending));
        }

        private static string ClassifyTelemetry(AvmEventRecord record)
        {
            var mechanism = record.Mechanism ?? string.Empty;
            var original = record.OriginalText ?? string.Empty;
            var combined = (mechanism + " " + original).ToLowerInvariant();

            if (combined.Contains("firmware") || combined.Contains("smbios") || combined.Contains("bios")
                || combined.Contains("serialnumber") || combined.Contains("systemmanufacturer"))
            {
                return "Firmware";
            }

            if (combined.Contains("cmcallback") || combined.Contains("reg") || combined.Contains("registry"))
            {
                return "Registry";
            }

            if (combined.Contains("openservice") || combined.Contains("enumservices"))
            {
                return "Service";
            }

            if (combined.Contains(@"\\.\") || combined.Contains("vmci") || combined.Contains("hgfs") || combined.Contains("device"))
            {
                return "Device";
            }

            if (combined.Contains("findfirstfile") || combined.Contains("findnextfile")
                || combined.Contains("dircontrol") || combined.Contains("directory"))
            {
                return "Directory";
            }

            if (combined.Contains("process") || combined.Contains("toolhelp") || combined.Contains("snapshot"))
            {
                return "Process";
            }

            if (combined.Contains("sleep") || combined.Contains("tickcount") || combined.Contains("rdtsc")
                || combined.Contains("performancecounter") || combined.Contains("timing"))
            {
                return "Timing";
            }

            if (combined.Contains("debug") || combined.Contains("beingdebugged") || combined.Contains("isdebuggerpresent"))
            {
                return "Debugger";
            }

            if (combined.Contains("createfile") || combined.Contains("networkqueryopen")
                || combined.Contains(".sys") || combined.Contains(".dll") || combined.Contains(".exe")
                || combined.Contains(@":\"))
            {
                return "File";
            }

            return "Other";
        }
    }
}
