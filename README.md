| Supported Targets | ESP32-H2 | ESP32-C6 |
| ----------------- | -------- | -------- |

# WORK IN PROGRESS (Benchmarking of PQ-noise on esp32 using zigbee)

## Objective 
  - Evaluate the feasability of implementing post-quantum noise on esp32 using zigbee, and benchmark it to compare it to regular x22519 noise. 
  
## Progess 
  - Used the ported noise-c library 
  - Added PQ exchanges from https://github.com/JoshuaRenckens/PQNoise_Master_Thesis to the noise-c 
  - Added the ported libsodium for esp32 
  - Added clean kybe rimplementation from https://github.com/PQClean/PQClean 
  - Wrote code to simulate a key exchange relying on ZIGBEES and benchmark it 
  - script to calculate interesting metrics using the console output. 
  - Added logic in our benchmark for other handshake patterns. All of the basic noise patterns should work now. 