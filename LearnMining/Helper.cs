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

        public static unsafe bool CompareTarget(uint* hash, uint* target, int length)
        {
            for (int i = length - 1; i >= 0; i--)
            {
                if (target[i] == 0 && hash[i] != 0)
                {
                    return false;
                }
                else if (target[i] == 0 && hash[i] == 0)
                {
                    continue;
                }
                else
                {
                    uint h = hash[i].SwapEndian();
                    uint t = target[i].SwapEndian();
                    if (h > t)
                    {
                        return false;
                    }
                    else if (h < t)
                    {
                        return true;
                    }
                    else if (target[i - 1] != 0) // && hash[i] == target[i]
                    {
                        h = hash[i - 1].SwapEndian();
                        t = target[i - 1].SwapEndian();
                        if (h > t)
                        {
                            return false;
                        }
                        else if (h < t)
                        {
                            return true;
                        }
                        // target will never have more than 2 items in it
                    }
                    // else -> rare case that hash[i]==target[i] && hash[i-1]==target[i-1] the remaining items must be 0
                }
            }
            return false;
        }

        public static uint[] ToTarget(uint compactTarget)
        {
            uint[] target = new uint[32 / 4];
            /*** Target ***/
            // if bits = XXYYYYYY then target = YYYYYY * 2^(8*(XX-3))
            // a * 2^k is the same as a << k
            int shift2 = 8 * ((byte)compactTarget - 3);
            // We have 3 bytes that we need to shift left and since we are using UInt32, 3 bytes (24 bit) can fall in 1 item or 2 max.
            // Each 32 bit shift moves to next index from the end. Each remainder is the shift of the remaining 3 bytes.
            // if the remainder is bigger than 8 bits the shifted 24 bits will go in next item.
            // 00000000_XXXXXXXX_XXXXXXXX_XXXXXXXX << 9 => 00000000_00000000_00000000_0000000X XXXXXXXX_XXXXXXXX_XXXXXXX0_00000000

            // NOTE: with the reversed endian used here, everything is in reverse:
            int index = shift2 / 32;
            int remShift = shift2 % 32;
            target[index] = (compactTarget & 0xffffff00) >> remShift;
            if (remShift > 8)
            {
                target[index + 1] = (compactTarget & 0xffffff00) << (32 - remShift);
            }

            return target;
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
