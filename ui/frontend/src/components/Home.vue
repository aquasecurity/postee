<template>
<div >
    <div class="row justify-content-end pb-3 pt-3 pr-3">
        <router-link :to="{name: 'add-plugin'}" class="col-3 btn btn-outline-primary">Add Integration</router-link>
    </div>
    <div class="row row-cols-1 row-cols-md-3">
        <PluginCard v-for="(plugin, index) in plugins"
            :key="index"
            :type="plugin.type"
            :name="plugin.name"
            :id="plugin.id"
            :enable="plugin.enable">
        </PluginCard>
    </div>
</div>
</template>
<script>
import PluginCard from './PluginCard.vue';
import { mapState} from 'vuex'

export default {
    components: {
        PluginCard
    },
    computed: {
        ...mapState({
            plugins (state) {
                return state.config.entries
            }
        })
    },
}
</script>