import main as TestModule

def test_keypair():
    pub,pri = TestModule.genKey()
    key = TestModule.M2Crypto.RSA.load_key_string(pub+pri)
    assert key.check_key() == True

def main():
    test_keypair()

if __name__ == "__main__":
    main()
