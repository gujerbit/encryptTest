<template>
  <div id="container">
    <div class="input-field">
      <textarea v-model="encrypt.value" />
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
        <button v-if="encrypt.type !== ''" @click="encryptValue()">encrypt</button>
        <button v-if="encrypt.type.includes('AES')" @click="decryptValue()">decrypt</button>
      </div>
      <textarea readonly :value="encrypt.result" />
    </div>
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
      result: '',
    });

    const encryptValue = async () => {
      let { data } = await axios.get(`/encrypt/${encrypt.value.type}?param=${encodeURIComponent(encrypt.value.value)}`);
      encrypt.value.result = data;
    };
    const decryptValue = async () => {
      let { data } = await axios.get(`/decrypt/${encrypt.value.type}?param=${encodeURIComponent(encrypt.value.value)}`);
      encrypt.value.result = data;
    };

    return { encrypt, encryptValue, decryptValue };
  }
}
</script>

<style>
#container {
  width: 80%;
  margin: 0 auto;
  height: 100%;
}

.input-field {
  display: flex;
  justify-content: space-around;
  align-items: center;
  height: 100%;
}

.type-selection {
  display: flex;
  height: 10%;
}

textarea {
  width: 30%;
  height: 20%;
}
</style>