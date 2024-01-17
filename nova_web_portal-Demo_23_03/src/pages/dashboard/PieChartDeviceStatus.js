import { useState, useEffect } from 'react';
// material-ui
import { useTheme } from '@mui/material/styles';
// third-party
import ReactApexChart from 'react-apexcharts';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_DEVICE } from 'framework/caching/entity-cache';

// chart options
const pieChartOptions = {
    chart: {
        width: 300,
        type: 'pie',
        toolbar: {
            show: false
        }
    },
    dataLabels: {
        enabled: true
    },
    tooltip: {
        theme: 'light'
    },
    legend: {
        position: 'bottom'
    },
    responsive: [
        {
            breakpoint: 480,
            options: {
                chart: {
                    width: 200
                },
                legend: {
                    position: 'bottom'
                }
            }
        }
    ]
};

// ==============================|| INCOME AREA CHART ||============================== //

const PieChartDeviceStatus = ({ colors }) => {
    const theme = useTheme();

    const { primary, secondary } = theme.palette.text;
    const line = theme.palette.divider;

    const [options, setOptions] = useState(pieChartOptions);
    const [series, setSeries] = useState();
    const [labels, setLabels] = useState();

    useEffect(() => {
        const dataSub = serviceFactoryInstance.dataLoaderService
            .dataSub(`${ENTITY_NAME_DEVICE}>dashboard>device_status`)
            .subscribe((data) => {
                if (data) {
                    setOptions((prevState) => ({
                        ...prevState,
                        colors: colors,
                        labels: ['Offline', 'Pending', 'Online']
                    }));
                    setSeries(data.series);
                    setLabels(['Offline', 'Pending', 'Online']);
                }
            });
        return () => {
            dataSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    return <>{series && labels && <ReactApexChart options={options} series={series} type="pie" labels={labels} height={347} />}</>;
};

export default PieChartDeviceStatus;
