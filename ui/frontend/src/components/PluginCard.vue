<template>
  <div class="col mb-4">
    <div class="card text-center">
      <div class="card-header">
        {{ type }}
      </div>
      <div class="card-body">
        <h5 class="card-title">
          {{ type==="common" ? "Defaults":  name }}
          <span v-show="enable === true" class="badge bg-success text-light"
            >enabled</span
          >
        </h5>

        <h6 class="card-subtitle text-muted">{{ sentCount }} scans received</h6>

        <router-link
          :to="{ name: 'plugin', params: { id: id } }"
          class="btn btn-link"
          >Edit</router-link
        >
        <button type="button" @click="doRemove" class="btn btn-link">
          Remove
        </button>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  props: ["type", "name", "id", "enable"],
  data() {
    return {
      sentCount: 10,
    };
  },
  methods: {
    doRemove() {
      this.$store.commit("removeSettings", this.id);
    },
  },
};
</script>