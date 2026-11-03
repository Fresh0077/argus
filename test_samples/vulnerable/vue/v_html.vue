<template>
  <article>
    <h1>评论</h1>
    <div v-html="comment"></div>
  </article>
</template>

<script setup>
import { ref, onMounted } from 'vue';

const comment = ref('');

onMounted(() => {
  const params = new URLSearchParams(window.location.search);
  comment.value = params.get('text') ?? '';
});
</script>
