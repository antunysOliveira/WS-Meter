using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

// MDPK header layout (CTPAX-X Team 2024 unmdpk.bms reference):
//
//   0x00..0x03  "MDPK"                magic
//   0x04..0x05  u16 LE version
//   0x06..0x07  u16 LE file_count     (version < 5)
//   0x06..0x09  u32 LE file_count     (version >= 5, OUR CASE version=6)
//   0x0A..0x19  16-byte ASCII+padding date/timestamp
//   0x1A..      TOC entries begin     (offset 26)
//
// TOC entry layout (68 bytes each):
//   [0..3]   u32 LE FileOffs   (absolute offset into pak)
//   [4..7]   u32 LE FileSize   (compressed / on-disk bytes)
//   [8..11]  u32 LE FileUnPk   (uncompressed bytes)
//   [12]     u8  FilePack      (0=stored, 1=bzip2, 2=brotli)
//   [13..67] 55-byte null-padded ASCII filename

struct TocEntry
{
    public string Name;
    public long Offset;           // absolute byte offset into pak
    public long Size;             // compressed (on-disk) byte count
    public long UncompressedSize; // decompressed byte count
    public byte Flags;            // 0 = stored, 2 = brotli
}

class PakExtract
{
    const int TocStart  = 26;    // TOC entries begin at byte 26
    const int NameLen   = 55;    // null-padded name field width
    const int EntrySize = 4 + 4 + 4 + 1 + NameLen;  // 68 bytes total

    static List<TocEntry> ParseToc(byte[] bytes)
    {
        if (bytes.Length < TocStart || Encoding.ASCII.GetString(bytes, 0, 4) != "MDPK")
            throw new InvalidDataException("Not an MDPK file");

        ushort version = BitConverter.ToUInt16(bytes, 4);
        long fileCount;
        if (version < 5)
            fileCount = BitConverter.ToUInt16(bytes, 6);
        else
            fileCount = BitConverter.ToUInt32(bytes, 6);

        // Sanity: TOC + all entries must fit inside file.
        if (TocStart + fileCount * EntrySize > bytes.Length)
            throw new InvalidDataException("MDPK header: fileCount=" + fileCount + " exceeds file size");

        var result = new List<TocEntry>((int)fileCount);
        for (long i = 0; i < fileCount; i++)
        {
            long p = TocStart + i * EntrySize;
            long offs = BitConverter.ToUInt32(bytes, (int)p);
            long size = BitConverter.ToUInt32(bytes, (int)(p + 4));
            long unsz = BitConverter.ToUInt32(bytes, (int)(p + 8));
            byte flag = bytes[p + 12];
            int nameStart = (int)(p + 13);
            int nameEnd = NameLen;
            for (int k = 0; k < NameLen; k++)
                if (bytes[nameStart + k] == 0) { nameEnd = k; break; }
            string name = Encoding.ASCII.GetString(bytes, nameStart, nameEnd);
            result.Add(new TocEntry { Name = name, Offset = offs, Size = size, UncompressedSize = unsz, Flags = flag });
        }
        return result;
    }

    static int Main(string[] args)
    {
        if (args.Length >= 2 && args[0] == "--list")
        {
            var bytes = File.ReadAllBytes(args[1]);
            if (bytes.LongLength > int.MaxValue)
            {
                Console.Error.WriteLine("ERROR: pak file exceeds 2 GiB (" + bytes.LongLength + " bytes) — extractor uses 32-bit offsets. Rewrite to streaming Read/Seek required.");
                return 5;
            }
            var toc = ParseToc(bytes);
            foreach (var e in toc)
                Console.WriteLine(e.Offset + "\t" + e.Size + "\t" + e.Name);
            return 0;
        }

        if (args.Length >= 1 && args[0] == "--extract-all")
        {
            if (args.Length < 3)
            {
                Console.Error.WriteLine("Usage: pakextract --extract-all <pak> <outdir>");
                return 2;
            }
            var pak = args[1]; var outdir = args[2];
            var bytes = File.ReadAllBytes(pak);
            if (bytes.LongLength > int.MaxValue)
            {
                Console.Error.WriteLine("ERROR: pak file exceeds 2 GiB (" + bytes.LongLength + " bytes) — extractor uses 32-bit offsets. Rewrite to streaming Read/Seek required.");
                return 5;
            }
            var toc = ParseToc(bytes);
            Directory.CreateDirectory(outdir);
            int n = 0;
            foreach (var e in toc)
            {
                var dest = Path.Combine(outdir, e.Name.Replace('/', Path.DirectorySeparatorChar));
                var destDir = Path.GetDirectoryName(dest);
                if (!string.IsNullOrEmpty(destDir)) Directory.CreateDirectory(destDir);
                byte[] payload;
                if (e.Flags == 0)
                {
                    payload = new byte[e.Size];
                    Array.Copy(bytes, (int)e.Offset, payload, 0, (int)e.Size);
                }
                else if (e.Flags == 2)
                {
                    payload = BrotliSharpLib.Brotli.DecompressBuffer(bytes, (int)e.Offset, (int)e.Size);
                    if (payload.Length != e.UncompressedSize)
                        throw new InvalidDataException("Brotli decompress size mismatch on " + e.Name + ": got " + payload.Length + ", expected " + e.UncompressedSize);
                }
                else
                {
                    throw new InvalidDataException("Unknown flags=" + e.Flags + " on entry " + e.Name + " (only 0/2 supported)");
                }
                File.WriteAllBytes(dest, payload);
                n++;
            }
            Console.WriteLine("Extracted " + n + " files to " + outdir);
            return 0;
        }

        Console.Error.WriteLine("Usage: pakextract --list <pak-file>");
        Console.Error.WriteLine("       pakextract --extract-all <pak> <outdir>");
        return 2;
    }
}
