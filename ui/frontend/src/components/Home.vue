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
import api from '../api'

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
    mounted() {
        if (this.$store.state.userInfo.authenticated) {
        this.$store.dispatch("load");
        this.$store.dispatch("loadStats");
        } else {
        if (this.$router.currentRoute.name!="login" ) {

            api.login().then(()=> {
            this.$store.commit("updateUserInfo", {authenticated: true});
            this.$store.dispatch("load");
            this.$store.dispatch("loadStats");

            }).catch(err => {
            if (err.response.status === 401) {
                this.$router.push({ name: "login" })
            }
            });

        }
        }

    },

}
</script>