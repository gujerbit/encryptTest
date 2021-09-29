<template>
  <div id="container">
    <div class="input-field">
      <textarea v-model="encrypt.value" placeholder="값 입력" required />
      <textarea v-if="encrypt.type.includes('AES')" v-model="encrypt.iv" placeholder="initial vector 입력" required />
      <textarea v-if="encrypt.type.includes('AES')" v-model="encrypt.key" placeholder="secretkey 입력" required />
    </div>
    <div class="type-selection">
      <select v-model="encrypt.type">
        <option disabled value="">select encrypt option</option>
        <option>SHA-224</option>
        <option>SHA-256</option>
        <option>SHA-384</option>
        <option>SHA-512</option>
        <option>AES-CBC</option>
        <option>AES-GCM</option>
      </select>
      <button v-if="encrypt.type !== '' && !encrypt.type.includes('AES')" @click="encryptValue()" :disabled="encrypt.value === ''">encrypt</button>
      <button v-if="encrypt.type !== '' && encrypt.type.includes('AES')" @click="encryptValue()" :disabled="encrypt.value === '' || encrypt.iv === '' || encrypt.key === ''">encrypt</button>
      <button v-if="encrypt.type.includes('AES')" @click="decryptValue()" :disabled="encrypt.value === '' || encrypt.iv === '' || encrypt.key === ''">decrypt</button>
    </div>
    <textarea readonly :value="encrypt.result" />
  </div>
</template>

<script>
import { ref } from 'vue';
import axios from 'axios';

export default {
  setup() {
    axios.defaults.baseURL = 'http://localhost:8090';
    const encrypt = ref({
      type: '',
      value: '',
      iv: '',
      key: '',
      result: '',
    });

    const encryptValue = async () => {
      if(encrypt.value.iv !== '' && checkByteLength(encrypt.value.iv) !== 16) {
        alert(`해당 값은 ${16}byte 값을 가져야 합니다! (현재 ${checkByteLength(encrypt.value.iv)}byte)`);
        return;
      }

      if(encrypt.value.key !== '' && checkByteLength(encrypt.value.key) !== 32) {
        alert(`해당 값은 ${32}byte 값을 가져야 합니다! (현재 ${checkByteLength(encrypt.value.key)}byte)`);
        return;
      }

      if(encrypt.value.iv === '' && encrypt.value.key === '') {
        let { data } = await axios.get(`/encrypt/${encrypt.value.type}?param=${encodeURIComponent(encrypt.value.value)}`);
        encrypt.value.result = data;
      } else if(encrypt.value.iv !== '' && encrypt.value.key !== '') {
        let { data } = await axios.get(`/encrypt/${encrypt.value.type}?param=${encodeURIComponent(encrypt.value.value)}&iv=${encodeURIComponent(encrypt.value.iv)}&key=${encodeURIComponent(encrypt.value.key)}`);
        encrypt.value.result = data;
      }
    };
    const decryptValue = async () => {
      if(encrypt.value.iv !== '' && checkByteLength(encrypt.value.iv, 16) !== 16) {
        alert(`해당 값은 ${16}byte 값을 가져야 합니다! (현재 ${checkByteLength(encrypt.value.iv, 16)}byte)`);
        return;
      }

      if(encrypt.value.key !== '' && checkByteLength(encrypt.value.key, 32) !== 32) {
        alert(`해당 값은 ${32}byte 값을 가져야 합니다! (현재 ${checkByteLength(encrypt.value.key, 32)}byte)`);
      }

      let { data } = await axios.get(`/decrypt/${encrypt.value.type}?param=${encodeURIComponent(encrypt.value.value)}&iv=${encodeURIComponent(encrypt.value.iv)}&key=${encodeURIComponent(encrypt.value.key)}`);
      encrypt.value.result = data;
    };
    const checkByteLength = (value) => {
      let result = 0;

      for(let i = 0; i < value.length; i++) value.charCodeAt(i) > 127 ? result += 2 : result ++;

      return result;
    }

    return { encrypt, encryptValue, decryptValue };
  }
}
</script>

<style>
#container {
  width: 80%;
  margin: 0 auto;
  height: 100%;
  display: grid;
  grid-template-columns: repeat(3, 1fr);
}

.input-field {
  display: grid;
  grid-template-rows: repeat(3, 1fr);
}

.type-selection {
  display: flex;
  justify-content: space-around;
  align-items: center;
}
</style>