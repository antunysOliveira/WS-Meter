// Split a class-icons atlas into individual 22x22 PNGs by grid position.
// Warspear class_icons atlas layout (128x128):
//   5 columns x 4 rows, cell 22x22 with 1px spacing, origin (1,1).
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;

namespace WSEngine
{
    static class ImgpSplit
    {
        public static int Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: imgp-split <atlas.png> <out-dir>");
                return 2;
            }
            string inPath = args[0];
            string outDir = args[1];
            Directory.CreateDirectory(outDir);

            using (var atlas = new Bitmap(inPath))
            {
                int cell = 22;
                int step = 23;
                int cols = 5;
                int rows = 4;
                int gridIdx = 0;
                for (int row = 0; row < rows; row++)
                {
                    for (int col = 0; col < cols; col++)
                    {
                        int x = 1 + col * step;
                        int y = 1 + row * step;
                        if (x + cell > atlas.Width || y + cell > atlas.Height) continue;
                        using (var icon = new Bitmap(cell, cell, PixelFormat.Format32bppArgb))
                        using (var g = Graphics.FromImage(icon))
                        {
                            g.DrawImage(atlas, new Rectangle(0, 0, cell, cell),
                                new Rectangle(x, y, cell, cell), GraphicsUnit.Pixel);
                            string name = string.Format("grid_{0:D2}_r{1}c{2}.png", gridIdx, row, col);
                            icon.Save(Path.Combine(outDir, name), ImageFormat.Png);
                        }
                        gridIdx++;
                    }
                }
                Console.WriteLine("Wrote " + gridIdx + " icons to " + outDir);
            }
            return 0;
        }
    }
}
