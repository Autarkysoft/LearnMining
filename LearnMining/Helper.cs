using System;
using System.Linq;

namespace LearnMining
{
    public static class Helper
    {
        public static bool AskYesNo(string msg)
        {
            while (true)
            {
                Console.Write($"{msg}? (y/n) ");
                ConsoleKeyInfo keyInfo = Console.ReadKey(false);
                if (keyInfo.Key == ConsoleKey.Y || keyInfo.Key == ConsoleKey.N)
                {
                    Console.WriteLine();
                    return keyInfo.Key == ConsoleKey.Y;
                }
                Console.WriteLine();
            }
        }


        public static byte[] HexToBytes(string hex, bool reverse = false)
        {
            byte[] ba = new byte[hex.Length / 2];
            for (int i = 0; i < ba.Length; i++)
            {
                int hi = hex[i * 2] - 65;
                hi = hi + 10 + ((hi >> 31) & 7);

                int lo = hex[i * 2 + 1] - 65;
                lo = lo + 10 + ((lo >> 31) & 7) & 0x0f;

                ba[i] = (byte)(lo | hi << 4);
            }

            if (reverse)
            {
                Array.Reverse(ba);
            }

            return ba;
        }

        public static byte[] ReadHex(string msg, int size, bool reverse = false)
        {
            while (true)
            {
                Console.Write($"Enter {msg} in hexadecimal (base-16) format: ");
                string hex = Console.ReadLine().ToLower();
                if (!string.IsNullOrWhiteSpace(hex) &&
                    hex.Length == 2 * size &&
                    hex.All(c => "0123456789abcdef".Contains(c)))
                {
                    return HexToBytes(hex, reverse);
                }
            }
        }

        public static int ReadInt(int min, int max)
        {
            int res;
            do
            {
                Console.Write($"Enter a number between {min} and {max}: ");
            } while (!int.TryParse(Console.ReadLine(), out res) || res < min || res > max);

            return res;
        }

        public static uint ReadUInt32(string msg)
        {
            uint res;
            do
            {
                Console.Write($"Enter {msg}: ");
            } while (!uint.TryParse(Console.ReadLine(), out res));

            return res;
        }





        public static void PrintHashrate(ulong hashCount, double seconds)
        {
            int res = (int)(hashCount / seconds);
            string mhs = (res <= 10_000) ? $"{(double)res / 1000:N1}" : $"{res / 1000:N0}";
            Console.WriteLine($"Hashrate is: {res:N0} H/sec = {mhs} MH/sec");
        }

    }
}
