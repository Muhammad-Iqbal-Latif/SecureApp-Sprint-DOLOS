import os
from dolos import serve

if __name__=='__main__':
    serve(os.getenv('DOLOS_HOST','127.0.0.1'),int(os.getenv('DOLOS_PORT','5000')))
