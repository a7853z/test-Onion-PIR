# A testing project for Onion-PIR 
This project could be viewed as a simple Client-Server application of [Onion-PIR](https://github.com/mhmughees/Onion-PIR), it uses Onion-PIR as the basic algorithm. The server will provide PIR service for clients. 

Please follow OnionPIR's README instructions to install following dependencies:
### Dependencies
- [Microsoft Seal version 3.5.1](https://github.com/microsoft/SEAL/tree/3.5.1)
- [NFLlib](https://github.com/quarkslab/NFLlib) 


## Compilation

1. After you finish installing the above dependencies. Now clone test-Onion-PIR and enter the test-Onion-PIR directory. 
2. Then build the project using following commands:
```
cmake . -DCMAKE_BUILD_TYPE=Release -DNTT_AVX2=ON -DSEAL_USE_ZLIB=OFF -DSEAL_USE_MSGSL=OFF
make
```
it will generate two binary files:Server and Client

3. Download test data files:[pir_data](https://pan.baidu.com/s/1ByRJugpP1i7ryst3t-etOA?pwd=pf7e) , the test file query_data.csv contains 100 million records. You can use your own test file, but you have to modify the config files correspondingly.
4. Copy server.conf.sample to server.conf  and copy client.conf.sample to client.conf. Use these files as default config files or modify your config files.
5. Run `./server` to start server. The first time you run, it will take some time to preprocess data.
6. Run `./client` to start client. The first time you run, it will take some time to preprocess data. Input the query id and the server will return its data. 

 
