import os
from ..migrate import migrate

def main():
    if os.getenv('SPYDERPAY_ENV') not in ('prelicense','test'):raise SystemExit('Refusing non-prelicense environment')
    print('Schema version:',migrate(os.environ['SPYDERPAY_PG_DSN']))

if __name__=='__main__':main()
