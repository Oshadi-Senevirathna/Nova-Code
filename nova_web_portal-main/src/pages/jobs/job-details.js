import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import serviceFactoryInstance from 'framework/services/service-factory';
import { LinearProgress } from '../../../node_modules/@mui/material/index';
import { ENTITY_NAME_FRONTEND_JOBS } from 'framework/caching/entity-cache';
import { Card, CardContent } from '../../../node_modules/@mui/material/index';
// material-ui
import { Grid, Typography } from '@mui/material';
// third party
// project import

// ============================|| FIREBASE - LOGIN ||============================ //

const DetailsPage = ({ title }) => {
    const [job, setJob] = useState();
    const params = useParams();

    useEffect(() => {
        document.title = title;
    }, []);

    useEffect(() => {
        const jobsSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_FRONTEND_JOBS).subscribe((data) => {
            if (data && params.UUID) {
                var job = data.filter((jobTemp) => {
                    return jobTemp.UUID === params.UUID;
                });
                if (job.length === 1) {
                    setJob(job[0]);
                }
            }
        });
        return () => {
            jobsSub.unsubscribe();
        };
    }, [params.UUID, serviceFactoryInstance.cache]);

    const runJob = () => {
        serviceFactoryInstance.dataLoaderService
            .runjob(job.UUID)
            .then((data) => {
                if (data.status) {
                    console.debug('Run request success');
                } else {
                    console.debug('Run request failed');
                }
            })
            .catch((reason) => {
                console.debug('Run request failed');
            });
    };

    return (
        <>
            {job && (
                <Card>
                    <CardContent>
                        <Grid container spacing={3}>
                            <Grid item xs={4}>
                                <Typography variant="subtitle1">Job Name</Typography>
                            </Grid>
                            <Grid item xs={8}>
                                <Typography>{job.job_name ? job.job_name : ''}</Typography>
                            </Grid>

                            <Grid item xs={4}>
                                <Typography variant="subtitle1">ID</Typography>
                            </Grid>
                            <Grid item xs={8}>
                                <Typography>{job.UUID ? job.UUID : ''}</Typography>
                            </Grid>

                            <Grid item xs={4}>
                                <Typography variant="subtitle1">Status</Typography>
                            </Grid>
                            <Grid item xs={8}>
                                <Typography>{job.status ? job.status : ''}</Typography>
                            </Grid>

                            <Grid item xs={4}>
                                <Typography variant="subtitle1">Errors</Typography>
                            </Grid>
                            <Grid item xs={8}>
                                <Typography>{job.error ? job.error : ''}</Typography>
                            </Grid>

                            <Grid item xs={12} md={12}>
                                {job.status === 'RUNNING' || job.status === 'COMPLETED' ? (
                                    <div>
                                        <Typography>Ongoing job progress</Typography>
                                        {job.job_progress === 0 || !job.job_progress ? (
                                            <LinearProgress />
                                        ) : (
                                            <LinearProgress variant="determinate" value={job.job_progress} />
                                        )}
                                        <Typography component={'span'} variant="body2" color="textSecondary">{`${Math.round(
                                            job.job_progress ? job.job_progress : 0
                                        )}% COMPLETE`}</Typography>
                                    </div>
                                ) : (
                                    <div>
                                        <LinearProgress variant="determinate" value={0} />
                                        <Typography component={'span'} variant="body2" color="textSecondary">{`${Math.round(
                                            0
                                        )}% COMPLETE`}</Typography>
                                    </div>
                                )}
                            </Grid>
                        </Grid>
                    </CardContent>
                </Card>
            )}
        </>
    );
};

export default DetailsPage;
