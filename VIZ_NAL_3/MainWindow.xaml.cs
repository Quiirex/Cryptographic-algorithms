using BCrypt.Net;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media.Imaging;

namespace VIZ_NAL_3
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private byte[] ključDES;
        private byte[] ključ3DES;

        public class DES
        {
            private DESCryptoServiceProvider des = new DESCryptoServiceProvider();

            public DES(string ključ)
            {
                des.Key = UTF8Encoding.UTF8.GetBytes(ključ);
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;
            }
            public void DES_Enkripcija(string path)
            {
                byte[] Biti = File.ReadAllBytes(path);
                byte[] kriptiraniBiti = des.CreateEncryptor().TransformFinalBlock(Biti, 0, Biti.Length);
                File.WriteAllBytes(path, kriptiraniBiti);
            }

            public void DES_Dekripcija(string path)
            {
                byte[] Biti = File.ReadAllBytes(path);
                byte[] dekriptiraniBiti = des.CreateDecryptor().TransformFinalBlock(Biti, 0, Biti.Length);
                File.WriteAllBytes(path, dekriptiraniBiti);
            }
        }
        public class TripleDES
        {
            private TripleDESCryptoServiceProvider tripledes = new TripleDESCryptoServiceProvider();

            public TripleDES(string ključ)
            {
                tripledes.Key = UTF8Encoding.UTF8.GetBytes(ključ);
                tripledes.Mode = CipherMode.ECB;
                tripledes.Padding = PaddingMode.PKCS7;
            }

            public void TripleDES_Enkripcija(string path)
            {
                byte[] Biti = File.ReadAllBytes(path);
                byte[] kriptiraniBiti = tripledes.CreateEncryptor().TransformFinalBlock(Biti, 0, Biti.Length);
                File.WriteAllBytes(path, kriptiraniBiti);
            }

            public void TripleDES_Dekripcija(string path)
            {
                byte[] Biti = File.ReadAllBytes(path);
                byte[] dekriptiraniBiti = tripledes.CreateDecryptor().TransformFinalBlock(Biti, 0, Biti.Length);
                File.WriteAllBytes(path, dekriptiraniBiti);
            }
        }
        public class AES
        {
            private AesCryptoServiceProvider aes = new AesCryptoServiceProvider();

            public AES(int velikostKljuča)
            {
                aes.KeySize = velikostKljuča;
                aes.GenerateKey();
                aes.GenerateIV();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                byte[] generiranKljuč = aes.Key;
                byte[] generiraniIV = aes.IV;
                File.WriteAllText(@"C:\Users\j6bou\Desktop\Key.txt", String.Empty);
                File.WriteAllText(@"C:\Users\j6bou\Desktop\IV.txt", String.Empty);
                System.IO.File.WriteAllText(@"C:\Users\j6bou\Desktop\Key.txt", Convert.ToBase64String(generiranKljuč));
                System.IO.File.WriteAllText(@"C:\Users\j6bou\Desktop\IV.txt", Convert.ToBase64String(generiraniIV));
            }

            public void AES_Enkripcija(string path)
            {
                byte[] Biti = File.ReadAllBytes(path);
                byte[] kriptiraniBiti = aes.CreateEncryptor().TransformFinalBlock(Biti, 0, Biti.Length);
                File.WriteAllBytes(path, kriptiraniBiti);
            }

            public void AES_Dekripcija(string path, byte[] ključ, byte[] IV)
            {
                byte[] Biti = File.ReadAllBytes(path);
                byte[] dekriptiraniBiti = aes.CreateDecryptor(ključ, IV).TransformFinalBlock(Biti, 0, Biti.Length);
                File.WriteAllBytes(path, dekriptiraniBiti);
            }
        }
        public class RSA
        {
            public static void GenerirajRSAključa(string javniKljučPath, string privatniKljučPath, int velikostKljuča)
            {
                using (var rsa = new RSACryptoServiceProvider(velikostKljuča))
                {
                    rsa.PersistKeyInCsp = false;

                    if (File.Exists(privatniKljučPath))
                    {
                        File.Delete(privatniKljučPath);
                    }

                    if (File.Exists(javniKljučPath))
                    {
                        File.Delete(javniKljučPath);
                    }

                    string javniKljuč = rsa.ToXmlString(false);
                    File.WriteAllText(javniKljučPath, javniKljuč);
                    string privatniKljuč = rsa.ToXmlString(true);
                    File.WriteAllText(privatniKljučPath, privatniKljuč);
                }
            }
            public static byte[] RSA_Enkripcija(string javniKljučPath, byte[] pusto, int velikostKljuča, string datotekaPath)
            {
                byte[] kriptirano;

                using (var rsa = new RSACryptoServiceProvider(velikostKljuča))
                {
                    rsa.PersistKeyInCsp = false;
                    string javniKljuč = File.ReadAllText(javniKljučPath);
                    rsa.FromXmlString(javniKljuč);
                    kriptirano = rsa.Encrypt(pusto, true);
                }
                File.WriteAllBytes(datotekaPath, kriptirano);
                return kriptirano;
            }
            public static byte[] RSA_Dekripcija(string privatniKljučPath, byte[] kriptirano, int velikostKljuča, string datotekaPath)
            {
                byte[] dekriptirano;

                using (var rsa = new RSACryptoServiceProvider(velikostKljuča))
                {
                    rsa.PersistKeyInCsp = false;
                    string privatniKljuč = File.ReadAllText(privatniKljučPath);
                    rsa.FromXmlString(privatniKljuč);
                    dekriptirano = rsa.Decrypt(kriptirano, true);
                }
                File.WriteAllBytes(datotekaPath, dekriptirano);
                return dekriptirano;
            }
        }
        public MainWindow()
        {
            InitializeComponent();
            Uri iconUri = new Uri("pack://application:,,,/ikona.ico", UriKind.RelativeOrAbsolute);
            Icon = BitmapFrame.Create(iconUri);
        }
        private void button_Click(object sender, RoutedEventArgs e) //3DES Naloži
        {
            Microsoft.Win32.OpenFileDialog naloži3DES = new Microsoft.Win32.OpenFileDialog();
            naloži3DES.Filter = "All Files|*";
            naloži3DES.Title = "Izberi datoteko";

            if (naloži3DES.ShowDialog() == true)
            {
                textBox.Text = naloži3DES.FileName;
            }
        }

        private void button1_Click(object sender, RoutedEventArgs e) //3DES Kriptiraj
        {
            try
            {
                TripleDES tDES = new TripleDES(textBox1.Text);

                if (!String.IsNullOrEmpty(textBox.Text))
                {
                    MessageBox.Show("Kriptiram...");
                    tDES.TripleDES_Enkripcija(textBox.Text);
                    GC.Collect();
                    MessageBox.Show("Izbrana datoteka kriptirana z 3DES algoritmom!");
                }
                else
                {
                    MessageBox.Show("Datoteka ni bila izbrana!");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void button2_Click(object sender, RoutedEventArgs e) //3DES Dekriptiraj
        {
            try
            {
                TripleDES tDES = new TripleDES(textBox1.Text);

                if (!String.IsNullOrEmpty(textBox.Text))
                {
                    MessageBox.Show("Dekriptiram...");
                    tDES.TripleDES_Dekripcija(textBox.Text);
                    GC.Collect();
                    MessageBox.Show("Izbrana datoteka dekriptirana z 3DES algoritmom!");
                }
                else
                {
                    MessageBox.Show("Datoteka ni bila izbrana!");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void button3_Click(object sender, RoutedEventArgs e) //DES Naloži
        {
            Microsoft.Win32.OpenFileDialog naložiDES = new Microsoft.Win32.OpenFileDialog();
            naložiDES.Filter = "All Files|*";
            naložiDES.Title = "Izberi datoteko";

            if (naložiDES.ShowDialog() == true)
            {
                textBox2.Text = naložiDES.FileName;
            }
        }

        private void button4_Click(object sender, RoutedEventArgs e) //DES Kriptiraj
        {
            try
            {
                DES des = new DES(textBox3.Text);

                if (!String.IsNullOrEmpty(textBox2.Text))
                {
                    MessageBox.Show("Kriptiram...");
                    des.DES_Enkripcija(textBox2.Text);
                    GC.Collect();
                    MessageBox.Show("Izbrana datoteka kriptirana z DES algoritmom!");
                }
                else
                {
                    MessageBox.Show("Datoteka ni bila izbrana!");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void button5_Click(object sender, RoutedEventArgs e) //DES Dekriptiraj
        {
            try
            {
                DES des = new DES(textBox3.Text);

                if (!String.IsNullOrEmpty(textBox2.Text))
                {
                    MessageBox.Show("Dekriptiram...");
                    des.DES_Dekripcija(textBox2.Text);
                    GC.Collect();
                    MessageBox.Show("Izbrana datoteka dekriptirana z DES algoritmom!");
                }
                else
                {
                    MessageBox.Show("Datoteka ni bila izbrana!");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void button8_Click(object sender, RoutedEventArgs e) //Naloži DES ključ
        {
            Microsoft.Win32.OpenFileDialog naložiDESKljuč = new Microsoft.Win32.OpenFileDialog();
            naložiDESKljuč.Title = "Naloži DES ključ";
            naložiDESKljuč.Filter = "txt files(*.txt) | *.txt";

            if (naložiDESKljuč.ShowDialog() == true)
            {
                textBox3.Text = File.ReadAllText(naložiDESKljuč.FileName);
            }
        }

        private void button11_Click(object sender, RoutedEventArgs e) //Naloži 3DES ključ
        {
            Microsoft.Win32.OpenFileDialog naloži3DESKljuč = new Microsoft.Win32.OpenFileDialog();
            naloži3DESKljuč.Title = "Naloži 3DES ključ";
            naloži3DESKljuč.Filter = "txt files(*.txt) | *.txt";

            if (naloži3DESKljuč.ShowDialog() == true)
            {
                textBox1.Text = File.ReadAllText(naloži3DESKljuč.FileName);
            }
        }

        private void button6_Click(object sender, RoutedEventArgs e) //Generiraj DES ključ
        {
            CipherKeyGenerator generatorKljuča = new CipherKeyGenerator();
            generatorKljuča.Init(new KeyGenerationParameters(new SecureRandom(), 64));

            ključDES = generatorKljuča.GenerateKey();
            BigInteger bigInteger = new BigInteger(ključDES);

            Microsoft.Win32.SaveFileDialog shraniDESKljuč = new Microsoft.Win32.SaveFileDialog();
            shraniDESKljuč.Title = "Shrani DES ključ";
            shraniDESKljuč.Filter = "txt files(*.txt) | *.txt";

            var naOsemZnakov = bigInteger.ToString(16).Substring(0, 8);

            if (shraniDESKljuč.ShowDialog() == true)
            {
                File.WriteAllText(shraniDESKljuč.FileName, naOsemZnakov);
            }
        }

        private void button9_Click(object sender, RoutedEventArgs e) //Generiraj 3DES ključ
        {
            CipherKeyGenerator generatorKljuča = new CipherKeyGenerator();
            generatorKljuča.Init(new KeyGenerationParameters(new SecureRandom(), 112));

            ključ3DES = generatorKljuča.GenerateKey();
            BigInteger bigInteger = new BigInteger(ključ3DES);

            Microsoft.Win32.SaveFileDialog shrani3DESKljuč = new Microsoft.Win32.SaveFileDialog();
            shrani3DESKljuč.Title = "Shrani 3DES ključ";
            shrani3DESKljuč.Filter = "txt files(*.txt) | *.txt";

            var naŠestnajstZnakov = bigInteger.ToString(16).Substring(0, 16);

            if (shrani3DESKljuč.ShowDialog() == true)
            {
                File.WriteAllText(shrani3DESKljuč.FileName, naŠestnajstZnakov);
            }
        }

        private void button7_Click(object sender, RoutedEventArgs e) //AES naloži
        {
            Microsoft.Win32.OpenFileDialog naložiAES = new Microsoft.Win32.OpenFileDialog();
            naložiAES.Filter = "All Files|*";
            naložiAES.Title = "Izberi datoteko";

            if (naložiAES.ShowDialog() == true)
            {
                textBox4.Text = naložiAES.FileName;
            }
        }

        private void button13_Click(object sender, RoutedEventArgs e) //RSA naloži
        {
            Microsoft.Win32.OpenFileDialog naložiRSA = new Microsoft.Win32.OpenFileDialog();
            naložiRSA.Filter = "All Files|*";
            naložiRSA.Title = "Izberi ključ";

            if (naložiRSA.ShowDialog() == true)
            {
                textBox6.Text = naložiRSA.FileName;
            }
        }

        private void button10_Click(object sender, RoutedEventArgs e) //AES kriptiraj
        {
            try
            {
                if (!String.IsNullOrEmpty(textBox8.Text))
                {
                    if (textBox8.Text == "128" || textBox8.Text == "192" || textBox8.Text == "256")
                    {
                        AES aes = new AES(Convert.ToInt32(textBox8.Text));

                        if (!String.IsNullOrEmpty(textBox4.Text))
                        {
                            MessageBox.Show("Kriptiram...");
                            aes.AES_Enkripcija(textBox4.Text);
                            GC.Collect();
                            MessageBox.Show("Izbrana datoteka kriptirana z AES algoritmom!");
                        }
                        else
                        {
                            MessageBox.Show("Datoteka ni bila izbrana!");
                        }
                    }
                    else
                    {
                        MessageBox.Show("Vnesena velikost ključa ne ustreza!");
                    }
                }
                else
                {
                    MessageBox.Show("Določite velikost ključa!");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void button12_Click(object sender, RoutedEventArgs e) //AES dekriptiraj
        {
            try
            {
                if (!String.IsNullOrEmpty(textBox5.Text))
                {
                    if (!String.IsNullOrEmpty(textBox7.Text))
                    {
                        AES aes = new AES(Convert.ToInt32(textBox8.Text));

                        if (!String.IsNullOrEmpty(textBox4.Text))
                        {
                            MessageBox.Show("Dekriptiram...");
                            aes.AES_Dekripcija(textBox4.Text, Convert.FromBase64String(textBox5.Text), Convert.FromBase64String(textBox7.Text));
                            GC.Collect();
                            MessageBox.Show("Izbrana datoteka dekriptirana z AES algoritmom!");
                            textBox5.Clear();
                            textBox7.Clear();
                        }
                        else
                        {
                            MessageBox.Show("Datoteka ni bila izbrana!");
                        }
                    }
                    else
                    {
                        MessageBox.Show("Izberite IV!");
                    }
                }
                else
                {
                    MessageBox.Show("Izberite ključ!");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void button14_Click(object sender, RoutedEventArgs e) //Naloži AES ključ
        {
            Microsoft.Win32.OpenFileDialog naložiAESključ = new Microsoft.Win32.OpenFileDialog();
            naložiAESključ.Filter = "All Files|*";
            naložiAESključ.Title = "Izberi AES ključ";

            if (naložiAESključ.ShowDialog() == true)
            {
                string text = System.IO.File.ReadAllText(naložiAESključ.FileName);
                textBox5.Text = text;
            }
        }

        private void button15_Click(object sender, RoutedEventArgs e) //Naloži AES IV
        {
            Microsoft.Win32.OpenFileDialog naložiAESiv = new Microsoft.Win32.OpenFileDialog();
            naložiAESiv.Filter = "All Files|*";
            naložiAESiv.Title = "Izberi AES IV";

            if (naložiAESiv.ShowDialog() == true)
            {
                string text = System.IO.File.ReadAllText(naložiAESiv.FileName);
                textBox7.Text = text;
            }
        }

        private void button16_Click(object sender, RoutedEventArgs e) //RSA kriptiraj
        {
            if (!String.IsNullOrEmpty(textBox9.Text))
            {
                if (!String.IsNullOrEmpty(textBox6.Text))
                {
                    Microsoft.Win32.OpenFileDialog naložiJavniKljuč = new Microsoft.Win32.OpenFileDialog();
                    naložiJavniKljuč.Filter = "All Files|*";
                    naložiJavniKljuč.Title = "Izberi javni ključ";
                    var tekst = File.ReadAllBytes(textBox6.Text);

                    if (naložiJavniKljuč.ShowDialog() == true)
                    {
                        try
                        {
                            RSA.RSA_Enkripcija(naložiJavniKljuč.FileName, tekst, Convert.ToInt32(textBox9.Text), textBox6.Text);
                            MessageBox.Show("Izbrana datoteka kriptirana z RSA algoritmom!");
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show(ex.ToString());
                        }
                    }
                }
                else
                {
                    MessageBox.Show("Datoteka ni bila izbrana!");
                }
            }
            else
            {
                MessageBox.Show("Določite velikost ključa!");
            }
        }
        private void button17_Click(object sender, RoutedEventArgs e) //RSA dekriptiraj
        {
            if (!String.IsNullOrEmpty(textBox9.Text))
            {
                if (!String.IsNullOrEmpty(textBox6.Text))
                {
                    Microsoft.Win32.OpenFileDialog naložiPrivatniKljuč = new Microsoft.Win32.OpenFileDialog();
                    naložiPrivatniKljuč.Filter = "All Files|*";
                    naložiPrivatniKljuč.Title = "Izberi privatni ključ";
                    var tekst = File.ReadAllBytes(textBox6.Text);

                    if (naložiPrivatniKljuč.ShowDialog() == true)
                    {
                        try
                        {
                            RSA.RSA_Dekripcija(naložiPrivatniKljuč.FileName, tekst, Convert.ToInt32(textBox9.Text), textBox6.Text);
                            MessageBox.Show("Izbrana datoteka dekriptirana z RSA algoritmom!");
                        }
                        catch (Exception)
                        {
                            MessageBox.Show("Uporabljen je bil nepravilen privatni ključ!");
                        }
                    }
                }
                else
                {
                    MessageBox.Show("Datoteka ni bila izbrana!");
                }
            }
            else
            {
                MessageBox.Show("Določite velikost ključa!");
            }
        }

        private void button18_Click(object sender, RoutedEventArgs e) //RSA generiraj par ključev
        {
            var javniPath = "";
            var privatniPath = "";

            if (!String.IsNullOrEmpty(textBox9.Text))
            {
                if (textBox9.Text == "1024" || textBox9.Text == "2048")
                {
                    Microsoft.Win32.SaveFileDialog shraniRSAjavniKljuč = new Microsoft.Win32.SaveFileDialog();
                    shraniRSAjavniKljuč.Title = "Shrani RSA javni ključ";
                    shraniRSAjavniKljuč.Filter = "XML files(*.xml) | *.xml";

                    if (shraniRSAjavniKljuč.ShowDialog() == true)
                    {
                        javniPath = shraniRSAjavniKljuč.FileName;
                    }

                    Microsoft.Win32.SaveFileDialog shraniRSAprivatniKljuč = new Microsoft.Win32.SaveFileDialog();
                    shraniRSAprivatniKljuč.Title = "Shrani RSA privatni ključ";
                    shraniRSAprivatniKljuč.Filter = "XML files(*.xml) | *.xml";

                    if (shraniRSAprivatniKljuč.ShowDialog() == true)
                    {
                        privatniPath = shraniRSAprivatniKljuč.FileName;
                    }
                    try
                    {
                        RSA.GenerirajRSAključa(javniPath, privatniPath, Convert.ToInt32(textBox9.Text));
                        MessageBox.Show("Javni in privatni ključ sta bila shranjena!");
                        textBox9.Clear();
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(ex.ToString());
                    }
                }
                else
                {
                    MessageBox.Show("Vnesena velikost ključa ne ustreza!");
                }
            }
            else
            {
                MessageBox.Show("Določite velikost ključa!");
            }
        }

        private void button19_Click(object sender, RoutedEventArgs e) //Izberi Hash datoteko
        {
            Microsoft.Win32.OpenFileDialog naložiDatoteko = new Microsoft.Win32.OpenFileDialog();
            naložiDatoteko.Filter = "All Files|*";
            naložiDatoteko.Title = "Izberi poljubno datoteko";

            if (naložiDatoteko.ShowDialog() == true)
            {
                try
                {
                    textBox10.Text = naložiDatoteko.FileName;
                }
                catch (Exception)
                {
                    MessageBox.Show("Prišlo je do napake");
                }
            }
        }
        static string vHex(byte[] vnos) //Pretvori v hexadecimalno
        {
            if (vnos == null)
            {
                return string.Empty;
            }

            StringBuilder sBuilder = new StringBuilder();

            foreach (byte by in vnos)
            {
                sBuilder.Append(by.ToString("X2"));
            }

            return sBuilder.ToString();
        }
        private byte[] ComputeMD5Hash(string datoteka) //Izračunaj MD5 hash
        {
            byte[] rezultat = null;

            using (MD5 md5 = MD5.Create())
            {
                int buffer = 10 * 1024 * 1024;
                using (var stream = new BufferedStream(File.OpenRead(datoteka), buffer))
                {
                    rezultat = md5.ComputeHash(stream);
                }
            }
            return rezultat;
        }
        private string ComputeMD5Hash_Text(string tekst) //Izračunaj MD5 hash iz teksta
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] rezultat = md5.ComputeHash(Encoding.UTF8.GetBytes(tekst));
                StringBuilder sBuilder = new StringBuilder();

                for (int i = 0; i < rezultat.Length; i++)
                {
                    sBuilder.Append(rezultat[i].ToString("x2"));
                }
                return sBuilder.ToString();
            }
        }
        private byte[] ComputeSHA1Hash(string datoteka) //Izračunaj SHA-1 hash
        {
            byte[] rezultat = null;

            using (SHA1 sha1 = SHA1.Create())
            {
                int buffer = 10 * 1024 * 1024;
                using (var stream = new BufferedStream(File.OpenRead(datoteka), buffer))
                {
                    rezultat = sha1.ComputeHash(stream);
                }
            }
            return rezultat;
        }
        private string ComputeSHA1Hash_Text(string tekst) //Izračunaj SHA-1 hash iz teksta
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] rezultat = sha1.ComputeHash(Encoding.UTF8.GetBytes(tekst));
                StringBuilder sBuilder = new StringBuilder();

                for (int i = 0; i < rezultat.Length; i++)
                {
                    sBuilder.Append(rezultat[i].ToString("x2"));
                }
                return sBuilder.ToString();
            }
        }
        private byte[] ComputeSHA256Hash(string datoteka) //Izračunaj SHA-256 hash
        {
            byte[] rezultat = null;

            using (SHA256 sha256 = SHA256.Create())
            {
                int buffer = 10 * 1024 * 1024;
                using (var stream = new BufferedStream(File.OpenRead(datoteka), buffer))
                {
                    rezultat = sha256.ComputeHash(stream);
                }
            }
            return rezultat;
        }
        static string ComputeSHA256Hash_Text(string tekst)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] rezultat = sha256.ComputeHash(Encoding.UTF8.GetBytes(tekst));
                StringBuilder sBuilder = new StringBuilder();

                for (int i = 0; i < rezultat.Length; i++)
                {
                    sBuilder.Append(rezultat[i].ToString("x2"));
                }
                return sBuilder.ToString();
            }
        } //Izračunaj SHA-256 hash iz teksta
        private string ComputebCryptHash(string datoteka) //Izračunaj bCrypt hash
        {
            byte[] rezultat = null;
            rezultat = File.ReadAllBytes(datoteka);
            var rezultatStr = Encoding.UTF8.GetString(rezultat);
            var hash = BCrypt.Net.BCrypt.HashPassword(rezultatStr, 11);
            return hash;
        }
        private async void button20_Click(object sender, RoutedEventArgs e) //Hash gumb
        {
            if (!String.IsNullOrEmpty(textBox10.Text))
            {
                if (radioButton.IsChecked == true)
                {
                    textBox11.Clear();
                    textBox12.Clear();
                    string datoteka = textBox10.Text;

                    byte[] md5HashBytes = await Task.Run(() => ComputeMD5Hash(datoteka));

                    textBox11.Text = vHex(md5HashBytes);
                }
                else if (radioButton1.IsChecked == true)
                {
                    textBox11.Clear();
                    textBox12.Clear();
                    string datoteka = textBox10.Text;

                    byte[] Sha1HashBytes = await Task.Run(() => ComputeSHA1Hash(datoteka));

                    textBox11.Text = vHex(Sha1HashBytes);
                }
                else if (radioButton2.IsChecked == true)
                {
                    textBox11.Clear();
                    textBox12.Clear();
                    string datoteka = textBox10.Text;

                    byte[] Sha256HashBytes = await Task.Run(() => ComputeSHA256Hash(datoteka));

                    textBox11.Text = vHex(Sha256HashBytes);
                }
                else if (radioButton3.IsChecked == true)
                {
                    textBox11.Clear();
                    textBox12.Clear();
                    string datoteka = textBox10.Text;

                    string bCryptHash = await Task.Run(() => ComputebCryptHash(datoteka));

                    textBox11.Text = bCryptHash;
                }
                else
                {
                    MessageBox.Show("Izberi zgoščevalni algoritem!");
                }
            }
            else
            {
                MessageBox.Show("Izberi datoteko!");
            }
        }

        private void button22_Click(object sender, RoutedEventArgs e) //Preveri integriteto hasha
        {
            if (!String.IsNullOrEmpty(textBox11.Text))
            {
                if (!String.IsNullOrEmpty(textBox13.Text))
                {
                    if (textBox11.Text.Equals(textBox13.Text))
                    {
                        textBox12.Text = "Pravilna";
                    }
                    else
                    {
                        textBox12.Text = "Nepravilna";
                    }
                }
                else
                {
                    MessageBox.Show("Naloži hash, s katerim želiš izračunan hash primerjati!");
                }
            }
            else
            {
                MessageBox.Show("Najprej je potrebno izračunati hash vrednost!");
            }
        }

        private void button23_Click(object sender, RoutedEventArgs e) //Naloži prvotni hash
        {
            Microsoft.Win32.OpenFileDialog naložiHash = new Microsoft.Win32.OpenFileDialog();
            naložiHash.Filter = "All Files|*";
            naložiHash.Title = "Izberi hash datoteko";

            if (naložiHash.ShowDialog() == true)
            {
                try
                {
                    textBox13.Text = System.IO.File.ReadAllText(naložiHash.FileName);
                }
                catch (Exception)
                {
                    MessageBox.Show("Prišlo je do napake");
                }
            }
        }

        private void button21_Click(object sender, RoutedEventArgs e) //Shrani hash
        {
            Microsoft.Win32.SaveFileDialog shraniHash = new Microsoft.Win32.SaveFileDialog();
            shraniHash.Title = "Shrani hash datoteke";
            shraniHash.Filter = "Txt files(*.txt) | *.txt";

            if (shraniHash.ShowDialog() == true)
            {
                using (StreamWriter sw = new StreamWriter(shraniHash.FileName))
                {
                    sw.Write(textBox11.Text);
                }
            }
        }
        public static string generirajSol()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] sol = new byte[32];
            rng.GetBytes(sol);
            string temp = Convert.ToBase64String(sol);
            return temp;
        }
        private void button24_Click(object sender, RoutedEventArgs e) //Gumb registracija
        {
            if (!String.IsNullOrEmpty(textBox14.Text))
            {
                if (!String.IsNullOrEmpty(passwordBox.Password))
                {
                    if (radioButton4.IsChecked == true) //MD5
                    {
                        Microsoft.Win32.SaveFileDialog shraniUporabnika = new Microsoft.Win32.SaveFileDialog();
                        shraniUporabnika.Title = "Shrani uporabnika in geslo";
                        shraniUporabnika.Filter = "Txt files(*.txt) | *.txt";

                        if (shraniUporabnika.ShowDialog() == true)
                        {
                            using (StreamWriter sw = new StreamWriter(shraniUporabnika.FileName))
                            {
                                var sol = generirajSol();
                                var soljenoGeslo = ComputeMD5Hash_Text(sol + passwordBox.Password);

                                sw.Write(textBox14.Text + ";" + soljenoGeslo + ";" + sol);
                                textBox14.Clear();
                                passwordBox.Clear();
                                MessageBox.Show("Uporabnik registriran!");
                            }
                        }
                    }
                    else if (radioButton5.IsChecked == true) //SHA-1
                    {
                        Microsoft.Win32.SaveFileDialog shraniUporabnika = new Microsoft.Win32.SaveFileDialog();
                        shraniUporabnika.Title = "Shrani uporabnika in geslo";
                        shraniUporabnika.Filter = "Txt files(*.txt) | *.txt";

                        if (shraniUporabnika.ShowDialog() == true)
                        {
                            using (StreamWriter sw = new StreamWriter(shraniUporabnika.FileName))
                            {
                                var sol = generirajSol();
                                var soljenoGeslo = ComputeSHA1Hash_Text(sol + passwordBox.Password);

                                sw.Write(textBox14.Text + ";" + soljenoGeslo + ";" + sol);
                                textBox14.Clear();
                                passwordBox.Clear();
                                MessageBox.Show("Uporabnik registriran!");
                            }
                        }
                    }
                    else if (radioButton6.IsChecked == true) //SHA-256
                    {
                        Microsoft.Win32.SaveFileDialog shraniUporabnika = new Microsoft.Win32.SaveFileDialog();
                        shraniUporabnika.Title = "Shrani uporabnika in geslo";
                        shraniUporabnika.Filter = "Txt files(*.txt) | *.txt";

                        if (shraniUporabnika.ShowDialog() == true)
                        {
                            using (StreamWriter sw = new StreamWriter(shraniUporabnika.FileName))
                            {
                                var sol = generirajSol();
                                var soljenoGeslo = ComputeSHA256Hash_Text(sol + passwordBox.Password);

                                sw.Write(textBox14.Text + ";" + soljenoGeslo + ";" + sol);
                                textBox14.Clear();
                                passwordBox.Clear();
                                MessageBox.Show("Uporabnik registriran!");
                            }
                        }
                    }
                    else if (radioButton7.IsChecked == true) //bCrypt
                    {
                        Microsoft.Win32.SaveFileDialog shraniUporabnika = new Microsoft.Win32.SaveFileDialog();
                        shraniUporabnika.Title = "Shrani uporabnika in geslo";
                        shraniUporabnika.Filter = "Txt files(*.txt) | *.txt";

                        if (shraniUporabnika.ShowDialog() == true)
                        {
                            using (StreamWriter sw = new StreamWriter(shraniUporabnika.FileName))
                            {
                                var sol = generirajSol();
                                var soljenoGeslo = BCrypt.Net.BCrypt.HashPassword(sol + passwordBox.Password);

                                sw.Write(textBox14.Text + ";" + soljenoGeslo + ";" + sol);
                                textBox14.Clear();
                                passwordBox.Clear();
                                MessageBox.Show("Uporabnik registriran!");
                            }
                        }
                    }
                    else
                    {
                        MessageBox.Show("Izberi algoritem!");
                    }
                }
                else
                {
                    MessageBox.Show("Vpiši geslo!");
                }
            }
            else
            {
                MessageBox.Show("Vpiši uporabniško ime!");
            }
        }

        private void button25_Click(object sender, RoutedEventArgs e) //Gumb prijava
        {
            if (!String.IsNullOrEmpty(textBox15.Text))
            {
                if (!String.IsNullOrEmpty(passwordBox1.Password))
                {
                    if (radioButton4.IsChecked == true) //MD5
                    {
                        string vnos = File.ReadAllText(@"C:\Users\j6bou\Desktop\md5.txt");
                        string[] besede = vnos.Split(';');

                        var hash = besede[1];
                        var sol = besede[2];

                        var soljenoGeslo = ComputeMD5Hash_Text(sol + passwordBox1.Password);

                        if (hash.Equals(soljenoGeslo))
                        {
                            MessageBox.Show("Prijava uspešna!");
                            textBox15.Clear();
                            passwordBox1.Clear();
                        }
                        else
                        {
                            MessageBox.Show("Prijava neuspešna");
                        }
                    }
                    else if (radioButton5.IsChecked == true) //SHA1
                    {
                        string vnos = File.ReadAllText(@"C:\Users\j6bou\Desktop\sha1.txt");
                        string[] besede = vnos.Split(';');

                        var hash = besede[1];
                        var sol = besede[2];

                        var soljenoGeslo = ComputeSHA1Hash_Text(sol + passwordBox1.Password);

                        if (hash.Equals(soljenoGeslo))
                        {
                            MessageBox.Show("Prijava uspešna!");
                            textBox15.Clear();
                            passwordBox1.Clear();
                        }
                        else
                        {
                            MessageBox.Show("Prijava neuspešna");
                        }
                    }
                    else if (radioButton6.IsChecked == true) //SHA256
                    {
                        string vnos = File.ReadAllText(@"C:\Users\j6bou\Desktop\sha256.txt");
                        string[] besede = vnos.Split(';');

                        var hash = besede[1];
                        var sol = besede[2];

                        var soljenoGeslo = ComputeSHA256Hash_Text(sol + passwordBox1.Password);

                        if (hash.Equals(soljenoGeslo))
                        {
                            MessageBox.Show("Prijava uspešna!");
                            textBox15.Clear();
                            passwordBox1.Clear();
                        }
                        else
                        {
                            MessageBox.Show("Prijava neuspešna");
                        }
                    }
                    else if (radioButton7.IsChecked == true) //bCrypt
                    {
                        string vnos = File.ReadAllText(@"C:\Users\j6bou\Desktop\bCrypt.txt");
                        string[] besede = vnos.Split(';');

                        var sol = besede[2];

                        var soljenoGeslo = BCrypt.Net.BCrypt.HashPassword(sol + passwordBox1.Password);

                        if (BCrypt.Net.BCrypt.Verify(sol + passwordBox1.Password, soljenoGeslo))
                        {
                            MessageBox.Show("Prijava uspešna!");
                            textBox15.Clear();
                            passwordBox1.Clear();
                        }
                        else
                        {
                            MessageBox.Show("Prijava neuspešna");
                        }
                    }
                    else
                    {
                        MessageBox.Show("Izberi algoritem!");
                    }
                }
                else
                {
                    MessageBox.Show("Vpiši geslo!");
                }
            }
            else
            {
                MessageBox.Show("Vpiši uporabniško ime!");
            }
        }
    }
}
