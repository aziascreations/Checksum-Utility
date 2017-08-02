using DamienG.Security.Cryptography;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace Checksum_Utility {

    public partial class MainWindow : Window {
        // Source for the menu things: http://pietschsoft.com/post/2008/03/Add-System-Menu-Items-to-WPF-Window-using-Win32-API
        public const Int32 WM_SYSCOMMAND = 0x112;
        public const Int32 MF_SEPARATOR = 0x800;
        public const Int32 MF_BYPOSITION = 0x400;
        public const Int32 MF_STRING = 0x0;
        public const Int32 _AboutSysMenuID = 1000;

        [DllImport("user32.dll")]
        private static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);

        [DllImport("user32.dll")]
        private static extern bool InsertMenu(IntPtr hMenu, Int32 wPosition, Int32 wFlags, Int32 wIDNewItem, string lpNewItem);

        public Boolean isFileLoaded = false;
        public string selectedFilePath = "";

        public MainWindow() {
            InitializeComponent();
            progressBar.Visibility = Visibility.Hidden;
        }
        public IntPtr Handle {
            get {
                return new WindowInteropHelper(this).Handle;
            }
        }

        private void Window_Loaded(object sender, RoutedEventArgs e) {
            IntPtr systemMenuHandle = GetSystemMenu(this.Handle, false);

            InsertMenu(systemMenuHandle, 5, MF_BYPOSITION | MF_SEPARATOR, 0, string.Empty);
            InsertMenu(systemMenuHandle, 6, MF_BYPOSITION, _AboutSysMenuID, "About...");

            HwndSource source = HwndSource.FromHwnd(this.Handle);
            source.AddHook(new HwndSourceHook(WndProc));
        }

        private static IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled) {
            if (msg == WM_SYSCOMMAND) {
                switch (wParam.ToInt32()) {
                    case _AboutSysMenuID:
                        Window w = new AboutWindow();
                        w.Show();
                        handled = true;
                        break;
                }
            }
            return IntPtr.Zero;
        }

        private void checkBoxCRC32_Click(object sender, RoutedEventArgs e) {
            textBoxCRC32.IsEnabled = checkBoxCRC32.IsChecked.HasValue ? checkBoxCRC32.IsChecked.Value : false;
            buttonCopyCRC32.IsEnabled = checkBoxCRC32.IsChecked.HasValue ? checkBoxCRC32.IsChecked.Value : false;
            buttonVerifyCRC32.IsEnabled = checkBoxCRC32.IsChecked.HasValue ? checkBoxCRC32.IsChecked.Value : false;
        }

        private void checkBoxMD5_Click(object sender, RoutedEventArgs e) {
            textBoxMD5.IsEnabled = checkBoxMD5.IsChecked.HasValue ? checkBoxMD5.IsChecked.Value : false;
            buttonCopyMD5.IsEnabled = checkBoxMD5.IsChecked.HasValue ? checkBoxMD5.IsChecked.Value : false;
            buttonVerifyMD5.IsEnabled = checkBoxMD5.IsChecked.HasValue ? checkBoxMD5.IsChecked.Value : false;
        }

        private void checkBoxSHA1_Click(object sender, RoutedEventArgs e) {
            textBoxSHA1.IsEnabled = checkBoxSHA1.IsChecked.HasValue ? checkBoxSHA1.IsChecked.Value : false;
            buttonCopySHA1.IsEnabled = checkBoxSHA1.IsChecked.HasValue ? checkBoxSHA1.IsChecked.Value : false;
            buttonVerifySHA1.IsEnabled = checkBoxSHA1.IsChecked.HasValue ? checkBoxSHA1.IsChecked.Value : false;
        }

        private void checkBoxSHA256_Click(object sender, RoutedEventArgs e) {
            textBoxSHA256.IsEnabled = checkBoxSHA256.IsChecked.HasValue ? checkBoxSHA256.IsChecked.Value : false;
            buttonCopySHA256.IsEnabled = checkBoxSHA256.IsChecked.HasValue ? checkBoxSHA256.IsChecked.Value : false;
            buttonVerifySHA256.IsEnabled = checkBoxSHA256.IsChecked.HasValue ? checkBoxSHA256.IsChecked.Value : false;
        }

        private void checkBoxSHA512_Click(object sender, RoutedEventArgs e) {
            textBoxSHA512.IsEnabled = checkBoxSHA512.IsChecked.HasValue ? checkBoxSHA512.IsChecked.Value : false;
            buttonCopySHA512.IsEnabled = checkBoxSHA512.IsChecked.HasValue ? checkBoxSHA512.IsChecked.Value : false;
            buttonVerifySHA512.IsEnabled = checkBoxSHA512.IsChecked.HasValue ? checkBoxSHA512.IsChecked.Value : false;
        }

        private void buttonCopyCRC32_Click(object sender, RoutedEventArgs e) {
            Clipboard.SetText(Checksums.crc32);
        }

        private void buttonCopyMD5_Click(object sender, RoutedEventArgs e) {
            Clipboard.SetText(Checksums.md5);
        }

        private void buttonCopySHA1_Click(object sender, RoutedEventArgs e) {
            Clipboard.SetText(Checksums.sha1);
        }

        private void buttonCopySHA256_Click(object sender, RoutedEventArgs e) {
            Clipboard.SetText(Checksums.sha256);
        }

        private void buttonCopySHA512_Click(object sender, RoutedEventArgs e) {
            Clipboard.SetText(Checksums.sha512);
        }

        private void buttonVerifyCRC32_Click(object sender, RoutedEventArgs e) {
            TextBoxVerifyFileChecksum.Text = Checksums.crc32;
        }

        private void buttonVerifyMD5_Click(object sender, RoutedEventArgs e) {
            TextBoxVerifyFileChecksum.Text = Checksums.md5;
        }

        private void buttonVerifySHA1_Click(object sender, RoutedEventArgs e) {
            TextBoxVerifyFileChecksum.Text = Checksums.sha1;
        }

        private void buttonVerifySHA256_Click(object sender, RoutedEventArgs e) {
            TextBoxVerifyFileChecksum.Text = Checksums.sha256;
        }

        private void buttonVerifySHA512_Click(object sender, RoutedEventArgs e) {
            TextBoxVerifyFileChecksum.Text = Checksums.sha512;
        }

        private void buttonSelectFile_Click(object sender, RoutedEventArgs e) {
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();

            dlg.DefaultExt = "*";
            dlg.Filter = "Any file|*";

            Nullable<bool> result = dlg.ShowDialog();

            if(result.HasValue && result.Value) {
                isFileLoaded = true;
                selectedFilePath = dlg.FileName;
            } else {
                isFileLoaded = false;
                selectedFilePath = "";
            }

            clearFields();
            textBoxFilePath.Text = System.IO.Path.GetFileName(selectedFilePath);
        }

        private void clearFields() {
            textBoxCRC32.Text = "";
            textBoxMD5.Text = "";
            textBoxSHA1.Text = "";
            textBoxSHA256.Text = "";
            textBoxSHA512.Text = "";

            TextBoxVerifyFileChecksum.Text = "";
            TextBoxVerifyCustomChecksum.Text = "";

            verifyChecksums();
        }

        private Boolean verifyChecksums() {
            String fileChecksum = TextBoxVerifyFileChecksum.Text.Replace(" ", "");
            String customChecksum = TextBoxVerifyCustomChecksum.Text.Replace(" ", "");

            if (String.IsNullOrEmpty(fileChecksum) || String.IsNullOrEmpty(customChecksum)) {
                IconCompare.Foreground = new SolidColorBrush(Color.FromArgb(0x89, 0, 0, 0));
                return false;
            }

            if(fileChecksum.ToUpper().Equals(customChecksum.ToUpper())) {
                IconCompare.Foreground = new SolidColorBrush(Color.FromArgb(0xBF, 0x0A, 0xAC, 0x20));
                return true;
            } else {;
                IconCompare.Foreground = new SolidColorBrush(Color.FromArgb(0xBF, 0xAC, 0x0A, 0x0A));
                return false;
            }
        }

        private async void buttonCheckFile_Click(object sender, RoutedEventArgs e) {
            if(!isFileLoaded)
                return;

            clearFields();
            progressBar.Visibility = Visibility.Visible;

            if(checkBoxCRC32.IsChecked.HasValue && checkBoxCRC32.IsChecked.Value) {
                await Task.Run(() => calculateCRC32(selectedFilePath));
                textBoxCRC32.Text = Checksums.crc32;
            }
            if(checkBoxMD5.IsChecked.HasValue && checkBoxMD5.IsChecked.Value) {
                await Task.Run(() => calculateMD5(selectedFilePath));
                textBoxMD5.Text = Checksums.md5;
            }
            if(checkBoxSHA1.IsChecked.HasValue && checkBoxSHA1.IsChecked.Value) {
                await Task.Run(() => calculateSHA1(selectedFilePath));
                textBoxSHA1.Text = Checksums.sha1;
            }
            if(checkBoxSHA256.IsChecked.HasValue && checkBoxSHA256.IsChecked.Value) {
                await Task.Run(() => calculateSHA256(selectedFilePath));
                textBoxSHA256.Text = Checksums.sha256;
            }
            if(checkBoxSHA512.IsChecked.HasValue && checkBoxSHA512.IsChecked.Value) {
                await Task.Run(() => calculateSHA512(selectedFilePath));
                textBoxSHA512.Text = Checksums.sha512;
            }

            progressBar.Visibility = Visibility.Hidden;
        }

        public void calculateCRC32(string filepath) {
            Crc32 crc32 = new Crc32();
            String hash = String.Empty;

            //using(FileStream fs = File.Open(filepath, FileMode.Open))
            //    foreach(byte b in crc32.ComputeHash(fs)) hash += b.ToString("x2").ToLower();

            using(FileStream stream = File.OpenRead(filepath))
                foreach (byte b in crc32.ComputeHash(stream)) hash += b.ToString("x2").ToLower();

            Checksums.crc32 = hash;
        }

        public void calculateMD5(string filepath) {
            using(var md5 = MD5.Create()) {
                using(var stream = File.OpenRead(filepath)) {
                    Checksums.md5 = BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "‌​").ToLower();
                }
            }
        }

        public void calculateSHA1(string filepath) {
            using(FileStream stream = File.OpenRead(filepath)) {
                using(SHA1Managed sha = new SHA1Managed()) {
                    byte[] checksum = sha.ComputeHash(stream);
                    Checksums.sha1 = BitConverter.ToString(checksum).Replace("-", string.Empty);
                }
            }
        }

        public void calculateSHA256(string filepath) {
            using(FileStream stream = File.OpenRead(filepath)) {
                var sha = new SHA256Managed();
                byte[] checksum = sha.ComputeHash(stream);
                Checksums.sha256 = BitConverter.ToString(checksum).Replace("-", String.Empty);
            }
        }

        public void calculateSHA512(string filepath) {
            using(FileStream stream = File.OpenRead(filepath)) {
                var sha = new SHA512Managed();
                byte[] checksum = sha.ComputeHash(stream);
                Checksums.sha512 = BitConverter.ToString(checksum).Replace("-", String.Empty);
            }
        }
        private void TextBoxVerifyFileChecksum_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) {
            verifyChecksums();
        }

        private void TextBoxVerifyCustomChecksum_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) {
            // Messes with the "cursor position"
            //TextBoxVerifyCustomChecksum.Text = TextBoxVerifyCustomChecksum.Text.ToUpper();
            verifyChecksums();
        }

        private void Window_KeyDown(object sender, System.Windows.Input.KeyEventArgs e) {
            if (e.Key.ToString() == "F1") {
                Window w = new AboutWindow();
                w.Show();
            }
        }

        private void Window_Closed(object sender, EventArgs e) {
            Process.GetCurrentProcess().Kill();
        }
    }

    public class Checksums {
        public static string crc32 = "ERROR";
        public static string md5 = "ERROR";
        public static string sha1 = "ERROR";
        public static string sha256 = "ERROR";
        public static string sha512 = "ERROR";
    }
}
