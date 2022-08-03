<template>
<div >
    <div class="row justify-content-end pb-3 pr-3">
        <router-link id="add-route" :to="{name: 'add-route'}" class="btn btn-primary">Add Route</router-link>
    </div>
    <div class="row row-cols-1 row-cols-md-3">
        <RouteCard v-for="(route, index) in routes" :key="'route-' + index" :name="route.name" :actionCnt="actionCnt(route.actions)"/>
    </div>
</div>
</template>
<script>
import RouteCard from './RouteCard.vue';
import { mapState} from 'vuex'

export default {
    components: {
        RouteCard
    },
    methods: {
        actionCnt(actions) {
            return actions?actions.length: 0
        }
    },
    computed: {
        ...mapState({
            routes (state) {
                return state.routes.all
            }
        })
    }

}
</script>