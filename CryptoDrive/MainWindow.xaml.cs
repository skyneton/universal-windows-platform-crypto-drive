using CryptoDrive.Cryptography;
using CryptoDrive.FS;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Diagnostics;
using System.IO;
using WinRT.Interop;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace CryptoDrive
{
    /// <summary>
    /// An empty window that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainWindow : Window
    {
        private Fsp.FileSystemHost host;
        public MainWindow()
        {
            this.InitializeComponent();
            Closed += OnClose;
        }

        private void OnClose(object sender, WindowEventArgs e)
        {
            host?.Unmount();
        }

        private async void OnDirPathSelectorClick(object sender, RoutedEventArgs e)
        {
            var picker = new Windows.Storage.Pickers.FolderPicker();
            picker.SuggestedStartLocation = Windows.Storage.Pickers.PickerLocationId.Desktop;
            picker.FileTypeFilter.Add("*");
            InitializeWithWindow.Initialize(picker, Process.GetCurrentProcess().MainWindowHandle);
            var folder = await picker.PickSingleFolderAsync();
            if (folder != null)
            {
                dirPath.Text = folder.Path;
            }
        }

        private void OnStartButtonClick(object sender, RoutedEventArgs e)
        {
            if (host != null)
            {
                host.Unmount();
                host = null;
                startButton.Content = "Start";
                return;
            }
            if (!Directory.Exists(dirPath.Text))
            {
                _ = new ContentDialog()
                {
                    Title = "Error",
                    Content = "Directory does not exist.",
                    CloseButtonText = "OK",
                    XamlRoot = Content.XamlRoot
                }.ShowAsync();
                return;
            }
            host = new Fsp.FileSystemHost(new CryptoFileSystem(SimpleCrypt.GetCryptoKey(password.Text), dirPath.Text));
            host.Mount("Z:");
            startButton.Content = "Stop";
        }
    }
}
