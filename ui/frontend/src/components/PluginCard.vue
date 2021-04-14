<template>
  <div class="col mb-4">
    <div class="card text-left">
      <div class="card-header">{{ type }}</div>
      <div class="card-body">
        <div class="d-flex align-items-center">
          <div class="flex-grow-1">
            <h5 class="card-title">{{ type==="common" ? "Defaults":  name }}</h5>
          </div>
          <div>
            <span v-show="enable === true" class="badge bg-success text-light">enabled</span>
          </div>
        </div>

        <h6 class="card-subtitle text-muted">{{ sentCount }} scans received</h6>

      </div>
      <div class="card-footer text-center">
        <router-link
          :to="{ name: 'plugin', params: { id: id } }"
          class="btn btn-link"
          >Edit</router-link
        >
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
  }
};
</script>