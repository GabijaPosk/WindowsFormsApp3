using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;


namespace WindowsFormsApp3
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }



//Failo teksto šifravimas
        private void FailoSifrMygtukas_Click(object sender, EventArgs e)
        {

            byte[] iv = new byte[16]; // inicializavimo vektorius
            byte[] keyBytes = Encoding.UTF8.GetBytes(Raktas.Text); // raktas, kuris naudojamas užšifruoti tekstą
            byte[] encrypted;

            int keySize = keyBytes.Length * 8; // konvertuoju baitų dydį bitais

            if (keySize < 128)
            {
                // jei raktas yra per trumpas, prailginu jį iki 128 bitų naudodama SHA256 hash funkciją
                using (SHA256 sha256 = SHA256.Create())
                {
                    keyBytes = sha256.ComputeHash(keyBytes);
                }
            }
            else if (keySize < 192)
            {
                // jei raktas yra per trumpas, prailginu jį iki 192 bitų naudodama SHA384 hash funkciją
                using (SHA384 sha384 = SHA384.Create())
                {
                    keyBytes = sha384.ComputeHash(keyBytes);
                }
            }
            else if (keySize < 256)
            {
                // jei raktas yra per trumpas, prailginu jį iki 256 bitų naudodama SHA512 hash funkciją
                using (SHA512 sha512 = SHA512.Create())
                {
                    keyBytes = sha512.ComputeHash(keyBytes);
                }
            }

            // Jei raktas yra per ilgas, sutraukiu jį iki 256 bitų naudojant tik pirmus 32 baitus
            Array.Resize(ref keyBytes, 32);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = keyBytes;
                aesAlg.IV = iv;

                // Sukuriamas šifravimo objektas
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Nuskaitomas failas ir šifruojamas jo turinys
                using (FileStream fs = new FileStream(FailoPaieska.Text, FileMode.Open))
                {
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            fs.CopyTo(csEncrypt);
                            csEncrypt.FlushFinalBlock();
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                }
            }

            // Konvertuojamas užšifruotas teksto masyvas į base64 tekstą ir įdedamas į naują failą
            File.WriteAllText(FailoPaieska.Text + ".sifruotas", Convert.ToBase64String(encrypted));
        }





//Failo paieška
        private void FailoIssaugotiMygtukas_Click(object sender, EventArgs e)
        {
            OpenFileDialog op = new OpenFileDialog();
            op.DefaultExt = ".txt";

            DialogResult result = op.ShowDialog();
            if (result == DialogResult.OK) 

            {
                FailoPaieska.Text = op.FileName;
                using (StreamReader sr = new StreamReader(op.FileName))
                {
                    FailoSifr.Text = sr.ReadToEnd();
                }
            }
        }




        private void Form1_Load(object sender, EventArgs e)
        {

        }





//Teksto šifravimas
        private void TekstoSifrMygtukas_Click(object sender, EventArgs e)
        {
            byte[] iv = new byte[16];
            byte[] textBytes = Encoding.UTF8.GetBytes(SifrTekstas.Text);
            byte[] keyBytes = Encoding.UTF8.GetBytes(Raktas2.Text);
            byte[] encrypted;


            int keySize = keyBytes.Length * 8;

            if (keySize < 128)
            {
                using (SHA256 sha256 = SHA256.Create())
                {
                    keyBytes = sha256.ComputeHash(keyBytes);
                }
            }
            else if (keySize < 192)
            {
                using (SHA384 sha384 = SHA384.Create())
                {
                    keyBytes = sha384.ComputeHash(keyBytes);
                }
            }
            else if (keySize < 256)
            {
                using (SHA512 sha512 = SHA512.Create())
                {
                    keyBytes = sha512.ComputeHash(keyBytes);
                }
            }

            Array.Resize(ref keyBytes, 32);


            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = keyBytes;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(textBytes, 0, textBytes.Length);
                        csEncrypt.FlushFinalBlock();
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            SifrTekstasGautas.Text = Convert.ToBase64String(encrypted);
        }




        private void TekstoDesifrMygtukas_Click(object sender, EventArgs e)
        {
            string sifruotasTekstas = DesifrTekstas.Text;
            string slaptasRaktas = Raktas3.Text;

            byte[] slaptasRaktasBytes = Encoding.UTF8.GetBytes(slaptasRaktas);
            byte[] slaptasRaktasHash = SHA256.Create().ComputeHash(slaptasRaktasBytes);

            byte[] sifruotasTekstasBytes = Convert.FromBase64String(sifruotasTekstas);

            string desifruotasTekstas = "";
            using (Aes aes = Aes.Create())
            {
                aes.Key = slaptasRaktasHash;
                aes.IV = new byte[16];

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(sifruotasTekstasBytes, 0, sifruotasTekstasBytes.Length);
                    }
                    byte[] desifruotasTekstasBytes = ms.ToArray();
                    desifruotasTekstas = Encoding.UTF8.GetString(desifruotasTekstasBytes);
                }
            }
            DesifrTekstasGautas.Text = desifruotasTekstas;
        }




//Užšifruoto teksto išsaugojimas į failą
        private void SifrIssaugotiMygtukas_Click(object sender, EventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = "Text files (*.txt)|*.txt";
            saveFileDialog.Title = "Išsaugoti užšifruotą tekstą";

            if (saveFileDialog.ShowDialog() == DialogResult.OK)
            {
                using (StreamWriter sw = new StreamWriter(saveFileDialog.FileName))
                {
                    sw.Write(SifrTekstasGautas.Text);
                }
                SifrTekstoIssaugoti.Text = saveFileDialog.FileName;
            }
        }



//Dešifruoto teksto išsaugojimas į failą
        private void DesifrIssaugotiMygtukas_Click(object sender, EventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = "Text files (*.txt)|*.txt";
            saveFileDialog.Title = "Išsaugoti užšifruotą tekstą";

            if (saveFileDialog.ShowDialog() == DialogResult.OK)
            {
                using (StreamWriter sw = new StreamWriter(saveFileDialog.FileName))
                {
                    sw.Write(DesifrTekstasGautas.Text);
                }
                DesifrTekstoIssaugoti.Text = saveFileDialog.FileName;
            }
        }
    }
}
