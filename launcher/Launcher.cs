using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace ProxyBypass
{
    internal static class Program
    {
        internal const string ApiUrl = "http://127.0.0.1:8077";
        internal static string BaseDir;

        [STAThread]
        private static void Main()
        {
            BaseDir = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');

            bool created;
            using (var mutex = new Mutex(true, "Local\\ProxyBypassApp", out created))
            {
                if (!created)
                {
                    // Второй запуск: не открываем новое окно, а показываем уже существующее.
                    try
                    {
                        using (var show = EventWaitHandle.OpenExisting("Local\\ProxyBypassShow"))
                            show.Set();
                    }
                    catch
                    {
                        // Первый экземпляр ещё не успел создать событие — просто выходим.
                    }
                    return;
                }

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                if (!Backend.EnsureRunning())
                {
                    MessageBox.Show(
                        "Не удалось запустить локальный сервер Proxy Bypass.\n" +
                        "Проверьте, установлен ли Node.js (C:\\Program Files\\nodejs\\node.exe).",
                        "Proxy Bypass", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                using (var form = new MainForm())
                {
                    Application.Run(form);
                }
            }
        }
    }

    internal static class Backend
    {
        internal static bool EnsureRunning()
        {
            if (IsAlive()) return true;

            string node = NodePath();
            if (node == null) return false;

            var appDir = Path.Combine(Program.BaseDir, "app");
            var psi = new ProcessStartInfo(node, "server.mjs");
            psi.WorkingDirectory = appDir;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.EnvironmentVariables["PROXY_APP_DATA"] = Path.Combine(Program.BaseDir, "data");
            psi.EnvironmentVariables["PROXY_APP_PORT"] = "8077";
            // Окно и трей рисует сам лаунчер, сервер не должен открывать второе окно.
            psi.EnvironmentVariables["PROXY_APP_NO_WINDOW"] = "1";
            psi.EnvironmentVariables["PROXY_APP_NO_TRAY"] = "1";
            try
            {
                Process.Start(psi);
            }
            catch
            {
                return false;
            }

            for (var i = 0; i < 60; i++)
            {
                Thread.Sleep(500);
                if (IsAlive()) return true;
            }
            return false;
        }

        private static string NodePath()
        {
            var candidates = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "nodejs", "node.exe"),
                @"C:\Program Files\nodejs\node.exe",
                @"C:\Program Files (x86)\nodejs\node.exe"
            };
            foreach (var path in candidates)
                if (File.Exists(path)) return path;

            // последний шанс — node из PATH
            return "node.exe";
        }

        internal static bool IsAlive()
        {
            try
            {
                var request = (HttpWebRequest)WebRequest.Create(Program.ApiUrl + "/api/status");
                request.Timeout = 1200;
                request.Proxy = null;
                using (var response = (HttpWebResponse)request.GetResponse())
                    return response.StatusCode == HttpStatusCode.OK;
            }
            catch
            {
                return false;
            }
        }

        internal static void Shutdown()
        {
            try
            {
                var request = (HttpWebRequest)WebRequest.Create(Program.ApiUrl + "/api/shutdown");
                request.Method = "POST";
                request.ContentType = "application/json";
                request.Timeout = 3000;
                request.Proxy = null;
                request.ContentLength = 0;
                using (var response = (HttpWebResponse)request.GetResponse()) { }
            }
            catch
            {
                // Сервер уже мог остановиться.
            }
        }
    }

    internal sealed class MainForm : Form
    {
        private readonly WebView2 web;
        private readonly NotifyIcon tray;
        private readonly EventWaitHandle showEvent;
        private bool reallyClose;

        internal MainForm()
        {
            Text = "Proxy Bypass";
            Width = 1180;
            Height = 820;
            MinimumSize = new Size(900, 640);
            StartPosition = FormStartPosition.CenterScreen;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
            catch { }

            web = new WebView2();
            web.Dock = DockStyle.Fill;
            Controls.Add(web);

            var menu = new ContextMenuStrip();
            menu.Items.Add("Открыть окно", null, delegate { ShowWindow(); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Выход", null, delegate { ExitApplication(); });

            tray = new NotifyIcon();
            tray.Text = "Proxy Bypass";
            tray.ContextMenuStrip = menu;
            tray.Visible = true;
            try { tray.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
            catch { tray.Icon = SystemIcons.Application; }
            tray.DoubleClick += delegate { ShowWindow(); };

            showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, "Local\\ProxyBypassShow");
            var watcher = new Thread(delegate ()
            {
                while (true)
                {
                    showEvent.WaitOne();
                    try { BeginInvoke(new Action(ShowWindow)); }
                    catch { }
                }
            });
            watcher.IsBackground = true;
            watcher.Start();

            FormClosing += OnClosing;
            Shown += OnShown;
        }

        private async void OnShown(object sender, EventArgs e)
        {
            try
            {
                var userData = Path.Combine(Program.BaseDir, "data", "webview");
                Directory.CreateDirectory(userData);
                // Chromium не стартует с правами администратора без отключения песочницы,
                // а TUN без этих прав не поднять. Песочница остаётся у самого Edge.
                var options = new CoreWebView2EnvironmentOptions("--no-sandbox");
                var env = await CoreWebView2Environment.CreateAsync(null, userData, options);
                await web.EnsureCoreWebView2Async(env);

                var settings = web.CoreWebView2.Settings;
                settings.AreDefaultContextMenusEnabled = false;
                settings.IsStatusBarEnabled = false;
                settings.AreDevToolsEnabled = false;

                web.CoreWebView2.NewWindowRequested += delegate (object s, CoreWebView2NewWindowRequestedEventArgs args)
                {
                    args.Handled = true;
                    var uri = args.Uri ?? "";
                    if (uri.StartsWith(Program.ApiUrl, StringComparison.OrdinalIgnoreCase))
                        web.CoreWebView2.Navigate(uri);
                    else
                        try { Process.Start(uri); } catch { }
                };

                web.Source = new Uri(Program.ApiUrl + "/");
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    "Не удалось открыть окно приложения (WebView2).\n\n" + error.Message +
                    "\n\nУстановите Microsoft Edge WebView2 Runtime и запустите приложение снова.",
                    "Proxy Bypass", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                ExitApplication();
            }
        }

        private void OnClosing(object sender, FormClosingEventArgs e)
        {
            if (reallyClose) return;
            if (e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                tray.ShowBalloonTip(2500, "Proxy Bypass", "Свёрнуто в трей. Двойной щелчок — открыть.", ToolTipIcon.Info);
            }
        }

        private void ShowWindow()
        {
            Show();
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate();
            BringToFront();
        }

        private void ExitApplication()
        {
            reallyClose = true;
            tray.Visible = false;
            Backend.Shutdown();
            Close();
            Application.Exit();
        }
    }
}
