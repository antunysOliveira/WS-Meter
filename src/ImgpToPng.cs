// ==================== .imgp -> PNG converter ====================
//
// Warspear's .imgp format is trivial:
//   [magic 0x00013233 u32][width u32 LE][height u32 LE][zero u32]
//   [pixels: width * height * 4 bytes RGBA]
//
// CLI: imgp2png <input.imgp> <output.png>
//   OR: imgp2png <input_dir> <output_dir>  (batch convert)

using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;

namespace WSEngine
{
    static class ImgpToPng
    {
        public static int Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: imgp2png <in.imgp|indir> <out.png|outdir>");
                return 2;
            }
            try
            {
                if (Directory.Exists(args[0]))
                {
                    Directory.CreateDirectory(args[1]);
                    int n = 0;
                    foreach (var f in Directory.GetFiles(args[0], "*.imgp"))
                    {
                        string outPath = Path.Combine(args[1], Path.GetFileNameWithoutExtension(f) + ".png");
                        ConvertOne(f, outPath);
                        n++;
                    }
                    Console.WriteLine("Converted " + n + " files to " + args[1]);
                }
                else
                {
                    ConvertOne(args[0], args[1]);
                }
                return 0;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("ERROR: " + e.Message);
                return 3;
            }
        }

        static void ConvertOne(string inPath, string outPath)
        {
            byte[] bytes = File.ReadAllBytes(inPath);
            if (bytes.Length < 12) throw new InvalidDataException("File too small: " + inPath);
            // Header (12 bytes): [magic u32][width u32 LE][height u32 LE]
            const int HeaderSize = 12;
            int width = BitConverter.ToInt32(bytes, 4);
            int height = BitConverter.ToInt32(bytes, 8);
            if (width <= 0 || width > 4096 || height <= 0 || height > 4096)
                throw new InvalidDataException("Bad dimensions " + width + "x" + height + " in " + inPath);
            int expected = HeaderSize + width * height * 4;
            if (bytes.Length < expected)
                throw new InvalidDataException("Truncated: expected " + expected + " bytes for " + width + "x" + height + " RGBA, got " + bytes.Length);

            using (var bmp = new Bitmap(width, height, PixelFormat.Format32bppArgb))
            {
                var rect = new Rectangle(0, 0, width, height);
                var data = bmp.LockBits(rect, ImageLockMode.WriteOnly, PixelFormat.Format32bppArgb);
                try
                {
                    // Source is RGBA (byte order R,G,B,A).
                    // Bitmap Format32bppArgb wants BGRA byte order in memory.
                    // Swap R and B per pixel.
                    var scan = new byte[width * height * 4];
                    for (int i = 0; i < width * height; i++)
                    {
                        int src = HeaderSize + i * 4;
                        int dst = i * 4;
                        scan[dst + 0] = bytes[src + 2]; // B
                        scan[dst + 1] = bytes[src + 1]; // G
                        scan[dst + 2] = bytes[src + 0]; // R
                        scan[dst + 3] = bytes[src + 3]; // A
                    }
                    System.Runtime.InteropServices.Marshal.Copy(scan, 0, data.Scan0, scan.Length);
                }
                finally
                {
                    bmp.UnlockBits(data);
                }
                bmp.Save(outPath, ImageFormat.Png);
            }
        }
    }
}
