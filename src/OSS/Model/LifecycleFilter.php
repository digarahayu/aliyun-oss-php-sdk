<?php

namespace OSS\Model;


/**
 * Class LifecycleFilter
 * @package OSS\Model
 */
class LifecycleFilter
{

    /**
     * @var LifecycleNot[]|null
     */
    private $not;

    /**
     * LifecycleFilter constructor.
     * @param LifecycleNot[] $not
     */
    public function __construct($not=null)
    {
        $this->not = $not;
    }

    /**
     * Get Filter Not
     *
     * @return LifecycleNot[]
     */
    public function getNot()
    {
        return $this->not;
    }

    /**
     * Set Filter Not
     * @param LifecycleNot $not
     */
    public function addNot($not)
    {
        $this->not[] = $not;

    }


    /**
     * @param \SimpleXMLElement $xmlRule
     */
    public function appendToXml(&$xmlRule)
    {
        if(isset($this->not)){
            $xmlFilter = $xmlRule->addChild("Filter");
            foreach ($this->not as $not){
                $not->appendToXml($xmlFilter);
            }
        }


    }
}