using System;
using System.Runtime.CompilerServices;

namespace LearnMining.Cryptography
{
    /// <summary>
    /// https://tools.ietf.org/html/rfc7914
    /// </summary>
    public class Scrypt : IDisposable
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="costParam">CPU/memory cost parameter. 2^n</param>
        /// <param name="blockSizeFactor">The blocksize parameter</param>
        /// <param name="parallelization">Parallelization</param>
        public Scrypt(int costParam, int blockSizeFactor, int parallelization)
        {
            if (costParam <= 1 || (costParam & (costParam - 1)) != 0)
                throw new ArgumentException();
            if (blockSizeFactor <= 0)
                throw new ArgumentException();
            if (parallelization <= 0)
                throw new ArgumentException();
            //TODO: check outofmemory possibility

            n = costParam;
            n1 = n - 1;
            r = blockSizeFactor;
            p = parallelization;
            hmac = new HmacSha(new Sha256());
            kdf = new PBKDF2(1, hmac);

            blockSize = blockSizeFactor * 128;
            blockSizeUint = blockSize / 4;
            strongSaltSize = blockSize * parallelization;
        }



        private readonly int blockSize;

        /// <summary>
        /// r * 128 / 4 = r * 32
        /// </summary>
        private readonly int blockSizeUint;
        private readonly int r;
        private readonly int n;

        /// <summary>
        /// (n-1) which can be used for mod operations using bitwise AND
        /// </summary>
        private readonly int n1;
        private readonly int p;
        private readonly IHmacFunction hmac;
        private PBKDF2 kdf;
        private readonly int strongSaltSize;
        private uint[] expensiveSalt;
        private uint[] V;



        public byte[] GetBytes(byte[] password, byte[] salt, int dkLen)
        {
            byte[] dk1 = kdf.GetBytes(password, salt, p * 128 * r);

            expensiveSalt = new uint[dk1.Length / 4];
            V = new uint[blockSizeUint * n];

            int index = 0;
            int i = 0;
            while (i < dk1.Length)
            {
                expensiveSalt[index++] = unchecked((uint)(dk1[i++] | (dk1[i++] << 8) | (dk1[i++] << 16) | (dk1[i++] << 24)));
            }

            // TODO: explore parallelisation with Parallel.For loop. will need to create V inside ROMIX_Uint for each iteration though.
            for (int j = 0; j < p; j++)
            {
                ROMIX(j * blockSizeUint);
            }

            index = 0;
            i = 0;
            while (i < expensiveSalt.Length)
            {
                unchecked
                {
                    dk1[index++] = (byte)expensiveSalt[i];
                    dk1[index++] = (byte)(expensiveSalt[i] >> 8);
                    dk1[index++] = (byte)(expensiveSalt[i] >> 16);
                    dk1[index++] = (byte)(expensiveSalt[i] >> 24);
                    i++;
                }
            }


            return kdf.GetBytes(password, dk1, dkLen);
        }

        private void ROMIX(int index)
        {
            // X = block
            // V0 = X               V0 = block
            // X = BlockMix(X)
            // V1 = X               V1 = BlockMix(V0)
            // X = BlockMix(X)
            // V2 = X               V2 = BlockMix(V1)
            //                      V(n-1) = BlockMix(n-2)
            Array.Copy(expensiveSalt, index, V, 0, blockSizeUint);

            for (int i = 0; i < n - 1; i++)
            {
                BlockMix(V, i * blockSizeUint, V, (i + 1) * blockSizeUint);
            }

            uint[] x = new uint[blockSizeUint];
            BlockMix(V, (n - 1) * blockSizeUint, x, 0);

            for (int i = 0; i < n; i++)
            {
                int j = Integerify(x);
                XOR(x, V, j * blockSizeUint);

                uint[] xclone = new uint[x.Length];
                Array.Copy(x, xclone, x.Length);

                BlockMix(xclone, 0, x, 0);
            }
            Array.Copy(x, 0, expensiveSalt, index, x.Length);
        }

        private int Integerify(uint[] x)
        {
            // Interpret (B[2 * r - 1]) in (B[0] ... B[2 * r - 1]) as a little-endian integer and compute mod N

            // x always has blockSize(=r*128) items in byte[] or blockSizeUint(=r*32) items in uint[]
            // last 64 bytes = last 16*4 byte or 16 uint items in its uint[]

            // Since value of n is an integer, it will always be smaller than a uint so % n doesn't need more than 1 item from uint[]
            // calculating (% n) is a simple bitwise AND with (n-1) since n is a power of 2
            // finally cast to int doesn't lose anything since n is an int and mod is always smaller than n

            return (int)(x[x.Length - 16] & n1);
        }

        private void BlockMix(uint[] block, int blockIndex, uint[] dst, int dstIndex)
        {
            // Treat block as 2r 64 byte chunks
            uint[] x = new uint[16]; // (64/4)=16
            Array.Copy(block, blockIndex + blockSizeUint - x.Length, x, 0, x.Length);
            int i1 = 0;
            int i2 = r;
            for (int i = 0; i < 2 * r; i++)
            {
                XOR(x, block, blockIndex + (i * 16));
                Salsa(x);
                if ((i & 1) == 0) // i = 0,2,4,...
                {
                    Array.Copy(x, 0, dst, dstIndex + (i1++ * 16), x.Length);
                }
                else
                {
                    Array.Copy(x, 0, dst, dstIndex + (i2++ * 16), x.Length);
                }
            }
        }
        private unsafe void XOR(uint[] first, uint[] second, int index)
        {
            fixed (uint* fp = &first[0], sp = &second[0])
            {
                for (int i = 0; i < first.Length; i++)
                {
                    fp[i] ^= sp[i + index];
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint R(uint a, int b)
        {
            return unchecked((a << b) | (a >> (32 - b)));
        }
        private void Salsa(uint[] block)
        {
            uint[] x = new uint[block.Length];
            Array.Copy(block, x, block.Length);

            // loop is only repeating the process 4 times and since the value `i` is not used, there is no point in doing it this way:
            // for (int i = 8; i > 0; i -= 2) 
            // i+=2 or the reverse is only used when the `Rounds` (here=8) is unknown. you do a double round on each iteration
            unchecked
            {
                for (int i = 0; i < 4; i++)
                {
                    x[4] ^= R(x[0] + x[12], 7); x[8] ^= R(x[4] + x[0], 9);
                    x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);
                    x[9] ^= R(x[5] + x[1], 7); x[13] ^= R(x[9] + x[5], 9);
                    x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);
                    x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9);
                    x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);
                    x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9);
                    x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);

                    x[1] ^= R(x[0] + x[3], 7); x[2] ^= R(x[1] + x[0], 9);
                    x[3] ^= R(x[2] + x[1], 13); x[0] ^= R(x[3] + x[2], 18);
                    x[6] ^= R(x[5] + x[4], 7); x[7] ^= R(x[6] + x[5], 9);
                    x[4] ^= R(x[7] + x[6], 13); x[5] ^= R(x[4] + x[7], 18);
                    x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9);
                    x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);
                    x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9);
                    x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
                }
            }

            for (int i = 0; i < x.Length; i++)
            {
                block[i] += x[i];
            }
        }



        #region IDisposable Support
        private bool disposedValue = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (expensiveSalt != null)
                        Array.Clear(expensiveSalt, 0, expensiveSalt.Length);
                    expensiveSalt = null;

                    if (V != null)
                        Array.Clear(V, 0, V.Length);
                    V = null;
                }

                disposedValue = true;
            }
        }


        /// <summary>
        /// Releases all resources used by the current instance of the <see cref="Scrypt"/> class.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion

    }
}
