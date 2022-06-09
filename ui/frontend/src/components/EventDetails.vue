<template>
  <div>
      <table width="100%">
        <tbody>
        <tr v-for='(ev, index) in events' :key="index">
          <vue-json-pretty :deep="2" deepCollapseChildren showLength showSelectController :data="{ ev }"> </vue-json-pretty>
        </tr>
        </tbody>
      </table>
  </div>
</template>
<script>
import { mapState } from 'vuex'
import VueJsonPretty from 'vue-json-pretty'
import 'vue-json-pretty/lib/styles.css'

export default {
  components:{
    VueJsonPretty,
  },

  computed: {
    ...mapState({
      events (state) {
        return state.events.all
      }
    })
  }
}

</script>