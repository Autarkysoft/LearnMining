using System;
using System.Collections.Generic;
using System.Text;

namespace LearnMining.Cryptography
{
    // https://tools.ietf.org/html/rfc2104
    public class HmacSha : IHmacFunction
    {
        public HmacSha(IHashFunction shaBasedHashFunction)
        {
            if (shaBasedHashFunction == null)
                throw new ArgumentNullException(nameof(shaBasedHashFunction), "Hash function can not be null.");

            Hash = shaBasedHashFunction;
        }

        public HmacSha(IHashFunction shaBasedHashFunction, byte[] key)
        {
            if (shaBasedHashFunction == null)
                throw new ArgumentNullException(nameof(shaBasedHashFunction), "Hash function can not be null.");

            Hash = shaBasedHashFunction; // Note: hash needs to be set first or setkey will throw null exception.
            Key = key;
        }



        public IHashFunction Hash { get; set; }
        public int BlockSize => Hash.BlockByteSize;
        public int OutputSize => Hash.HashByteSize;
        byte[] opad, ipad;

        private byte[] _keyValue;
        public byte[] Key
        {
            get => _keyValue;
            set
            {
                if (value == null)
                    throw new ArgumentNullException("Key can not be null.");


                if (value.Length > Hash.BlockByteSize)
                {
                    _keyValue = Hash.ComputeHash(value);
                }
                else
                {
                    _keyValue = value.CloneByteArray();
                }

                // Now set pads
                opad = new byte[Hash.BlockByteSize];
                ipad = new byte[Hash.BlockByteSize];
                unsafe
                {
                    // Note (kp = _keyValue) can't assign to first item because key might be empty array which will throw an excpetion
                    fixed (byte* kp = _keyValue, op = &opad[0], ip = &ipad[0])
                    {
                        for (int i = 0; i < _keyValue.Length; i++)
                        {
                            op[i] = (byte)(kp[i] ^ 0x5c);
                            ip[i] = (byte)(kp[i] ^ 0x36);
                        }
                        for (int i = _keyValue.Length; i < opad.Length; i++)
                        {
                            op[i] = 0 ^ 0x5c;
                            ip[i] = 0 ^ 0x36;
                        }
                    }
                }
            }
        }


        // TODO: check behavior in case key was set (or other ctor with key was called) and then this function was called!
        // there might be some issue with pad
        public byte[] ComputeHash(byte[] data, byte[] key)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "Data can not be null.");

            Key = key; // This will check null, set _keyValue properly and initializes pads

            return Hash.ComputeHash(opad.ConcatFast(Hash.ComputeHash(ipad.ConcatFast(data))));
        }


        /// <summary>
        /// <see cref="ComputeHash(byte[], byte[])"/>
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public byte[] ComputeHash(byte[] data)
        {
            if (disposedValue)
                throw new ObjectDisposedException($"{nameof(HmacSha)} instance was disposed.");
            if (data == null)
                throw new ArgumentNullException(nameof(data), "Data can not be null.");
            if (_keyValue == null)
                throw new ArgumentNullException(nameof(Key), "Key must be set before calling this function");

            // Pads are already set
            return Hash.ComputeHash(opad.ConcatFast(Hash.ComputeHash(ipad.ConcatFast(data))));
        }





        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (_keyValue != null)
                        Array.Clear(_keyValue, 0, _keyValue.Length);
                    _keyValue = null;

                    if (Hash != null)
                        Hash.Dispose();
                    Hash = null;
                }

                disposedValue = true;
            }
        }

        /// <summary>
        /// Releases all resources used by the current instance of the <see cref="HmacSha"/> class.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}
