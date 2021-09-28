<template>
  <main>
    <main-component />
  </main>
</template>

<script>
import mainComponent from './components/MainComponent.vue';

export default {
  name: 'App',
  components: {
    mainComponent
  }
}
</script>

<style>
main {
  width: 100%;
  height: 50vh;
}
</style>
