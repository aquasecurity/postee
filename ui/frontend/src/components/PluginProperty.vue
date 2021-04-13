<template>
  <div v-show="show" class="form-group form-input">
    <label for="id">{{ label }}</label>
    <input
      :type="inputType"
      :value="value"
      :name="name"
      @input="inputHandler"
      class="form-control"
      :id="id"
    />
    <small
      v-show="!!description"
      id="description"
      class="form-text text-muted"
      >{{ description }}</small
    >
  </div>
</template>
<script>
export default {
  props: {
    name: String,
    inputType: {
        type: String,
        default: "input"
    },
    label: String,
    value: [String, Number],
    id: String,
    description: String,
    show: Boolean,
    inputHandler: Function,
  },
};
</script>