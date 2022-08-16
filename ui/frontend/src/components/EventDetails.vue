<template>
  <div id="event-list">
    <div class="card-header"><h3>Events</h3></div>
    <div class="card-body">All incoming events that Postee has received so far.</div>
    <json-viewer
        :value="events"
        :expand-depth=3
        copyable
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