<template>
  <div>
    <div class="row justify-content-end pb-3 pr-3">
      <button type="submit" class="btn btn-primary mr-2" @click="doSubmit">
        Submit
      </button>
      <button
        v-if="!!name"
        type="button"
        @click="doRemove"
        class="btn btn-outline-primary"
      >
        Remove
      </button>
    </div>
    <div class="card">
      <form @submit.prevent="doSubmit">
        <div class="card-body">
          <PluginProperty
            :id="'name'"
            :label="'Name'"
            :value="formValues.name"
            :errorMsg="errors['name']"
            :inputHandler="updateField"
            :validator="v(uniqueName)"
          />
          <div class="form-group form-input">
            <label class="form-label" for="input">REGO template:</label>

            <codemirror
              :value="formValues.body"
              :options="cmOptions"
              id="body"
              name="body"
              @input="updateBody"
            >
            </codemirror>

            <small class="form-text text-muted">
              REGO template to render received events
            </small>
          </div>
        </div>
      </form>
    </div>
  </div>
</template>

<script>
import { mapState } from "vuex";
import ValidationMixin from "./validator";
import FormFieldMixin from "./form";
import PluginProperty from "./PluginProperty.vue";
import { codemirror } from "vue-codemirror";

import "codemirror-rego/mode";
import "codemirror/lib/codemirror.css";

export default {
  data() {
    return {
      fields: {},
      errors: {},
      name: "",
      cmOptions: {
        tabSize: 4,
        mode: "rego",
        lineNumbers: true,
        line: true,
      },
    };
  },
  mixins: [FormFieldMixin, ValidationMixin],
  components: {
    PluginProperty,
    codemirror,
  },
  computed: {
    ...mapState({
      formValues(state) {
        //required for mixins
        const found = state.templates.all.filter(
          (item) => item.name === this.name
        );

        const result = found.length ? { ...found[0] } : {};

        return result;
      },
    }),
  },
  methods: {
    doSubmit() {
      if (!this.isFormValid()) {
        return;
      }

      if (this.name) {
        this.$store.dispatch("templates/update", {
          value: this.formValues,
          name: this.name,
        });
      } else {
        this.$store.dispatch("templates/add", this.formValues);
      }
      this.$router.push({ name: "templates" });
    },
    doRemove() {
      this.$store.dispatch("templates/remove", this.name);
      this.$router.push({ name: "templates" });
    },
    updateBody(v) {
      this.formValues.body = v;
    },
    uniqueName(label, value) {
      if (!value) {
        return `${label} is required`;
      }
      const found = this.$store.state.templates.all.filter(
        (item) => item.name === value
      );

      if (found.length > 0 && found[0].name != this.name) {
        return `${value} is not unique`;
      }
      return false;
    },
  },
  mounted() {
    this.name = this.$route.params.name;
  },
};
</script>
