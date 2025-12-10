import classes from './RightDiv.module.css';
import ScenarioBox from './ScenarioBox';
import detections from '../../detections.js';

const RightDiv = (props) => {
  const categoryKey = Object.keys(detections).find(
    key => detections[key].name.toLowerCase() === props.title.toLowerCase()
  );

  const categoryDetections = categoryKey ? detections[categoryKey].detections : [];

  return (
    <div className={classes.rightDiv}>
      <div className={classes.header}>
        <div className={classes.title} style={{ color: props.color }}>
          {props.title}
        </div>
        <div className={classes.image}>
          <img src={props.img_source} alt={props.title} />
        </div>
      </div>

      <div className={classes.scenario_div}>
        {categoryDetections.map(detection => (
          <ScenarioBox
            key={detection.id}
            name={detection.name}
            technique={detection.technique}
            scenario={detection.scenario}
            requirements={detection.requirements || []}
            basicQuery={detection.basicQuery}
            alertQuery={detection.alertQuery}
          />
        ))}
      </div>
    </div>
  );
};

export default RightDiv;
