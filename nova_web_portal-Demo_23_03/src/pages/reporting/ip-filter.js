const ipFilter = (instances, ipPre, ipStart, ipEnd) => {
    var filteredInstances = [];
    for (let i = 0; i < instances.length; i++) {
        const instance = instances[i];
        if (instance['ip_address']) {
            const lastDotIndex = instance['ip_address'].lastIndexOf('.');
            const ipPreIns = instance['ip_address'].slice(0, lastDotIndex);
            if (ipPreIns === ipPre) {
                const ipPostIns = parseInt(Number(instance['ip_address'].slice(lastDotIndex + 1)));
                if (ipPostIns >= ipStart && ipPostIns <= ipEnd) {
                    filteredInstances.push(instance);
                }
            }
        }
    }

    return filteredInstances;
};

export default ipFilter;
