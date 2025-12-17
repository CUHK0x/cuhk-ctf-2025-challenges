import numpy as np

flag = open('flag.txt', 'r').read().strip()
enc_flag = np.array(list(map(ord, flag))).reshape((-1, 2))
diff = (enc_flag[:, np.newaxis, :] - enc_flag[np.newaxis, :, :])

print(((diff)**2).sum(axis=2).tolist(), end='')
