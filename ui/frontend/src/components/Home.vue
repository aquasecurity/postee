<template>
<div >
    <div class="row justify-content-end pb-3 pt-3 pr-3">
        <router-link :to="{name: 'add-plugin'}" class="col-3 btn btn-outline-primary">Add Integration</router-link>
    </div>
    <div class="row row-cols-1 row-cols-md-3">
        <PluginCard v-for="(plugin, index) in plugins" :key="index" :title="plugin.title"></PluginCard>
    </div>
</div>
</template>
<script>
import PluginCard from './PluginCard.vue';

export default {
    components: {
        PluginCard
    },
    data() {
        return {
            plugins: [
                {title: "Jira" },
                {title: "Slack" },
                {title: "Teams" },
                {title: "Jira" },
                {title: "Email" }
            ]
        };
    }
}
</script>