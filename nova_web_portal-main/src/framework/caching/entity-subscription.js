import { BehaviorSubject } from 'rxjs';

class EntitySubscription {
    constructor(
        service,
        entity,
        tenant,
        noOfInstances,
        startOfInstances,
        queryString,
        fields,
        sortField,
        sortDirection,
        filterField,
        filterValue
    ) {
        this.service = service;
        this.entity = entity;
        this.dataSubject = new BehaviorSubject();
        this.countSubject = new BehaviorSubject();
        this.noOfInstances = noOfInstances;
        this.startOfInstances = startOfInstances;
        this.tenant = tenant;
        this.queryString = queryString;
        this.fields = fields;
        this.sortField = sortField;
        this.sortDirection = sortDirection;
        this.filterField = filterField;
        this.filterValue = filterValue;
        this.data = [];
        this.count = 0;
        this.load();
    }

    load() {
        this.entity.noOfInstances = this.noOfInstances;
        this.entity.startOfInstances = this.startOfInstances;
        this.entity.tenant = this.tenant;
        this.entity.queryString = this.queryString;
        this.entity.fields = this.fields;
        this.entity.sortField = this.sortField;
        this.entity.sortDirection = this.sortDirection;
        this.entity.filterField = this.filterField;
        this.entity.filterValue = this.filterValue;
        console.log('EntitySubscription:load ', this.entity);
        this.service.loadData(this.entity, (data) => {
            this.data = data.instances;
            this.count = data.count ? data.count : data.instances.length;
            if (this.data !== null && this.data !== undefined) {
                this.dataSubject.next(this.data);
            } else {
                this.dataSubject.next([]);
            }
            this.countSubject.next(this.count);
        });
    }

    add() {
        console.log('EntitySubscription:add ', this.entity);
        if (this.startOfInstances >= this.count - this.noOfInstances || !this.noOfInstances) {
            this.load();
        }
    }

    delete(newData) {
        console.log('EntitySubscription:delete ', this.entity);
        var dataTemp = [];

        newData.forEach((newDataItem) => {
            dataTemp = [
                ...dataTemp,
                ...this.data.filter((dataTempItem) => {
                    return newDataItem._id === dataTempItem._id;
                })
            ];
        });
        console.log(this.data, newData, dataTemp);
        if (dataTemp.length > 0) {
            this.load();
        }
    }

    update(newData) {
        console.log('EntitySubscription:update ', this.entity);
        var dataTemp = [];
        newData.forEach((newDataItem) => {
            dataTemp = [
                ...dataTemp,
                ...this.data.filter((dataTempItem) => {
                    return newDataItem._id === dataTempItem._id;
                })
            ];
        });
        if (dataTemp.length > 0) {
            this.load();
        }
    }

    getObservable(tenant, noOfInstances, startOfInstances, queryString, fields, sortField, sortDirection, filterField, filterValue) {
        if (
            this.tenant !== tenant ||
            this.noOfInstances !== noOfInstances ||
            this.startOfInstances !== startOfInstances ||
            this.queryString !== queryString ||
            this.fields !== fields ||
            this.sortField !== sortField ||
            this.sortDirection !== sortDirection ||
            this.filterField !== filterField ||
            this.filterValue !== filterValue
        ) {
            this.noOfInstances = noOfInstances;
            this.startOfInstances = startOfInstances;
            this.tenant = tenant;
            this.queryString = queryString;
            this.fields = fields;
            this.sortField = sortField;
            this.sortDirection = sortDirection;
            this.filterField = filterField;
            this.filterValue = filterValue;
            this.load();
        }
        return this.dataSubject.asObservable();
    }

    getCountObservable() {
        return this.countSubject.asObservable();
    }

    close() {
        this.dataSubject.observers.forEach((observer) => observer.complete());
    }
}

export default EntitySubscription;
