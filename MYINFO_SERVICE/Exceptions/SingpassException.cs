using System;

namespace MYINFO_SERVICE.Exceptions
{
    public class SingpassException : Exception
    {
        public SingpassException()
        { }

        public SingpassException(string message) : base(message)
        {
        }

        public SingpassException(string message, Exception e) : base(message, e)
        {
        }
    }
}
