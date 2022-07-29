<template>
  <div>
    <json-viewer
        :value="events"
        :expand-depth=3
        copyable
        boxed
    ></json-viewer>
  </div>
</template>
<script>
import { mapState } from 'vuex'
import JsonViewer from 'vue-json-viewer'

export default {
  components:{
    JsonViewer,
  },

  computed: {
    ...mapState({
      events (state) {
        return state.events.all
      }
    })
  },
}

</script>